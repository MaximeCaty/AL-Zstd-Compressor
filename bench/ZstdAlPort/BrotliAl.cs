using System.Reflection;

namespace ZstdAlPort;

/*
    Brotli (RFC 7932) encoder and decoder written the AL way, to measure ratio and AL speed. Statements an AL version would
    execute are counted per stage (St) ; text operations (Append / ToText / Substring of the output window) in TextOps.

    Encoder : the AL zstd parser (ParseHook : same matches, same parse cost) -> brotli commands (insert, copy, distance) ;
    meta-blocks of up to MetaMax bytes, one block type per category (no block switching), NPOSTFIX = NDIRECT = 0 ;
    literals : 64 contexts of the 2 previous bytes, mode chosen per meta-block (LSB6 / MSB6 / UTF8 / SIGNED, sampled
    estimate), contexts clustered into prefix codes (greedy pair merge while it saves bits) ; distance short codes against
    the 4-distance ring (last, 2nd..4th, last +-1..3, 2nd +-1..3), implicit distance 0 in command codes 0-127 ;
    prefix codes : simple (<= 4 symbols) or complex (code length code, zero runs with code 17), lengths <= 15 ;
    a meta-block that does not beat its raw size is written uncompressed. Final empty last meta-block.
    Decoder : complete RFC 7932 (block switching, context maps with RLE / IMTF, simple and complex prefix codes with
    repeat codes, NPOSTFIX / NDIRECT, static dictionary + 121 transforms, uncompressed and metadata meta-blocks).
    Prefix codes decoded with a 2-level table (8-bit root), LSB-first bit reader.
*/
public sealed class BrotliAl
{
    // ------------------------------------------------------------------------------------------------ counters
    public const int EParse = 0, ECtx = 1, ECluster = 2, EHuff = 3, EEmit = 4, DHdr = 5, DCmd = 6, DLit = 7, DDist = 8, DCopy = 9;
    public static readonly string[] StageNames = { "parse (zstd model)", "contexts + histograms", "context clustering", "prefix codes", "bit output",
        "headers + tables", "commands", "literals", "distances", "copies / output" };
    public readonly long[] St = new long[10];
    public long TextOps, DecAppends, EncAppends, DictRefs, BlockSwitches;
    public double ParseMs; // AL zstd parse time model (ms), for the parse stage
    public int MetaMax = 1 << 20;
    public ZstdLevel Level = ZstdLevel.Heavy;
    public ZstdProfile Profile = ZstdProfile.General;

    static readonly byte[] Dict = LoadDict();
    static byte[] LoadDict()
    {
        var p = Path.Combine(AppContext.BaseDirectory, "brotli-dictionary.bin");
        return File.ReadAllBytes(p);
    }
    static readonly int[] NDBits = { 0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5 };
    static readonly int[] DOffset = MakeDOffset();
    static int[] MakeDOffset() { var o = new int[25]; for (int l = 4; l < 24; l++) o[l + 1] = o[l] + l * (1 << NDBits[l]); return o; }

    static readonly int[] InsBase = { 0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594 };
    static readonly int[] InsExtra = { 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24 };
    static readonly int[] CopyBase = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118 };
    static readonly int[] CopyExtra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24 };
    static readonly int[] CellIns = { 0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16 };
    static readonly int[] CellCopy = { 0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16 };
    static readonly int[] BlkBase = { 1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625 };
    static readonly int[] BlkExtra = { 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24 };
    static readonly int[] ClOrder = { 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    // ================================================================================================= bit writer (LSB first)
    ByteBuilder Out; ulong WAcc; int WCnt;
    void W(int n, long v)
    {
        if (n == 0) return;
        WAcc |= (ulong)v << WCnt; WCnt += n;
        while (WCnt >= 16) { Out.Append((byte)WAcc); Out.Append((byte)(WAcc >> 8)); WAcc >>= 16; WCnt -= 16; EncAppends++; }
    }
    void WAlign() { while (WCnt > 0) { Out.Append((byte)WAcc); WAcc >>= 8; WCnt = Math.Max(0, WCnt - 8); } WAcc = 0; WCnt = 0; }
    (int len, ulong acc, int cnt) Mark() => (Out.Length, WAcc, WCnt);
    void Rewind((int len, ulong acc, int cnt) m) { Out.Truncate(m.len); WAcc = m.acc; WCnt = m.cnt; }
    long BitPos() => Out.Length * 8L + WCnt;

    void WVarLen(int v) // NBLTYPES / NTREES - 1 (0..255)
    {
        if (v == 0) { W(1, 0); return; }
        W(1, 1);
        int n = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)v);
        W(3, n);
        if (n > 0) W(n, v - (1 << n));
    }

    // ================================================================================================= encoder
    readonly List<int> CIns = new(), CCopy = new(), CDist = new();
    int PendingLits;

    public byte[] Compress(byte[] input)
    {
        Out = new ByteBuilder(); WAcc = 0; WCnt = 0;
        CIns.Clear(); CCopy.Clear(); CDist.Clear(); PendingLits = 0;
        // parse with the AL zstd encoder
        var z = new ZstdAlEncoder();
        z.ParseHook = (e, start, size) =>
        {
            int pos = start;
            for (int i = 1; i <= e.SeqCount; i++)
            {
                int ll = e.SeqLitLen(i), ml = e.SeqMatchLen(i), off = e.SeqOff[i];
                CIns.Add(PendingLits + ll); CCopy.Add(ml); CDist.Add(off);
                PendingLits = 0;
                pos += ll + ml;
            }
            PendingLits += start + size - pos;
        };
        z.Compress(input, Level, Profile);
        ParseMs += z.Stats.EstimatedAlMs();
        if (PendingLits > 0 || CIns.Count == 0) { CIns.Add(PendingLits); CCopy.Add(0); CDist.Add(0); } // insert-only tail
        // stream header : WBITS
        int wbits = 16;
        while (wbits < 24 && (1 << wbits) - 16 < input.Length) wbits++;
        if (wbits == 16) W(1, 0);
        else if (wbits >= 18) { W(1, 1); W(3, wbits - 17); }
        else { W(1, 1); W(3, 0); W(3, 0); } // 17
        MaxBack = (1 << wbits) - 16;
        Rb = new[] { 16, 15, 11, 4 }; RbIdx = 0; // ring : last = Rb[(RbIdx + 3) & 3]
        int c0 = 0, pos0 = 0;
        while (c0 < CIns.Count)
        {
            int c1 = c0, mlen = 0;
            while (c1 < CIns.Count && (mlen == 0 || mlen + CIns[c1] + CCopy[c1] <= MetaMax)) { mlen += CIns[c1] + CCopy[c1]; c1++; }
            if (mlen > 0) WriteMetaBlock(input, pos0, mlen, c0, c1);
            pos0 += mlen; c0 = c1;
        }
        W(1, 1); W(1, 1); // ISLAST, ISLASTEMPTY
        WAlign();
        return Out.ToArray();
    }

    int MaxBack; int[] Rb; int RbIdx;
    int RbGet(int back) => Rb[(RbIdx + 3 - back) & 3]; // back 0 = last
    void RbPush(int d) { Rb[RbIdx] = d; RbIdx = (RbIdx + 1) & 3; }

    int DistCode(int d, out int extraBits, out int extra)
    {
        extraBits = 0; extra = 0;
        int last = RbGet(0), second = RbGet(1);
        if (d == last) return 0;
        if (d == second) return 1;
        if (d == RbGet(2)) return 2;
        if (d == RbGet(3)) return 3;
        int dl = d - last;
        if (dl >= -3 && dl <= 3) return dl switch { -1 => 4, 1 => 5, -2 => 6, 2 => 7, -3 => 8, _ => 9 };
        int ds = d - second;
        if (ds >= -3 && ds <= 3 && ds != 0) return ds switch { -1 => 10, 1 => 11, -2 => 12, 2 => 13, -3 => 14, _ => 15 };
        int dd = d + 3; // NPOSTFIX = NDIRECT = 0
        int nbits = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)dd) - 1;
        int prefix = (dd >> nbits) & 1;
        extraBits = nbits; extra = dd & ((1 << nbits) - 1);
        return 16 + 2 * (nbits - 1) + prefix;
    }

    static int InsCode(int v) { int c = 0; while (c < 23 && InsBase[c + 1] <= v) c++; return c; }
    static int CopyCode(int v) { int c = 0; while (c < 23 && CopyBase[c + 1] <= v) c++; return c; }

    void WriteMetaBlock(byte[] d, int start, int mlen, int c0, int c1)
    {
        var mark = Mark();
        var ringSave = ((int[])Rb.Clone(), RbIdx);
        long st0 = St[ECtx] + St[ECluster] + St[EHuff] + St[EEmit];
        // ---------------------------------------------------------------- command symbols (and ring simulation)
        int nCmd = c1 - c0;
        var cmdCode = new int[nCmd]; var dCode = new int[nCmd]; var dExtraBits = new int[nCmd]; var dExtra = new int[nCmd];
        var cmdHist = new int[704]; var distHist = new int[64];
        int pos = start;
        for (int k = 0; k < nCmd; k++)
        {
            int ins = CIns[c0 + k], copy = CCopy[c0 + k], dist = CDist[c0 + k];
            int ic = InsCode(ins);
            bool lastCmd = pos + ins >= start + mlen; // meta-block ends in the literals : copy and distance not coded
            int cc = CopyCode(Math.Max(2, copy));
            int dc = 0;
            if (!lastCmd)
            {
                dc = DistCode(dist, out dExtraBits[k], out dExtra[k]);
                if (dc != 0) RbPush(dist);
            }
            dCode[k] = lastCmd ? -1 : dc;
            int cell;
            if ((lastCmd || dc == 0) && ic < 8 && cc < 16) { cell = cc < 8 ? 0 : 1; dCode[k] = -1; }
            else
            {
                int ih = ic >> 3, ch = cc >> 3;
                cell = (ih, ch) switch { (0, 0) => 2, (0, 1) => 3, (1, 0) => 4, (1, 1) => 5, (0, 2) => 6, (2, 0) => 7, (1, 2) => 8, (2, 1) => 9, _ => 10 };
            }
            cmdCode[k] = cell * 64 + ((ic & 7) << 3) + (cc & 7);
            cmdHist[cmdCode[k]]++;
            if (dCode[k] >= 0) distHist[dCode[k]]++;
            pos += ins + copy;
            St[ECtx] += 14; // AL : ins / copy code lookups, ring compare chain, cell, histograms
        }
        // ---------------------------------------------------------------- literal contexts : mode choice (sampled) + clustering
        int mode = ChooseMode(d, start, c0, c1);
        var litHist = new int[64][];
        for (int c = 0; c < 64; c++) litHist[c] = new int[256];
        pos = start;
        for (int k = 0; k < nCmd; k++)
        {
            int ins = CIns[c0 + k];
            for (int i = 0; i < ins; i++)
            {
                int p = pos + i;
                int p1 = p >= 1 ? d[p - 1] : 0, p2 = p >= 2 ? d[p - 2] : 0;
                litHist[BrotliData.ContextLut[mode * 512 + p1] | BrotliData.ContextLut[mode * 512 + 256 + p2]][d[p]]++;
            }
            St[ECtx] += 3L * ins + 2;
            pos += ins + CCopy[c0 + k];
        }
        var cmap = Cluster(litHist, out int nTrees, out var treeHist);
        // ---------------------------------------------------------------- prefix codes
        var litLen = new int[nTrees][]; var litCode = new int[nTrees][];
        for (int t = 0; t < nTrees; t++) (litLen[t], litCode[t]) = PrepareCode(treeHist[t]);
        var (cmdLen, cmdCd) = PrepareCode(cmdHist);
        var (distLen, distCd) = PrepareCode(distHist);
        // ---------------------------------------------------------------- header
        W(1, 0); // ISLAST
        int nib = mlen - 1 < (1 << 16) ? 4 : mlen - 1 < (1 << 20) ? 5 : 6;
        W(2, nib - 4); W(nib * 4, mlen - 1);
        W(1, 0); // ISUNCOMPRESSED
        W(1, 0); W(1, 0); W(1, 0); // NBLTYPESL / I / D = 1
        W(2, 0); W(4, 0); // NPOSTFIX, NDIRECT
        W(2, mode);
        WVarLen(nTrees - 1);
        if (nTrees > 1) WriteContextMap(cmap, nTrees);
        WVarLen(0); // NTREESD = 1
        for (int t = 0; t < nTrees; t++) WritePrefixCode(litLen[t], treeHist[t], 256);
        WritePrefixCode(cmdLen, cmdHist, 704);
        WritePrefixCode(distLen, distHist, 64);
        // ---------------------------------------------------------------- commands
        pos = start;
        for (int k = 0; k < nCmd; k++)
        {
            int ins = CIns[c0 + k], copy = CCopy[c0 + k];
            int cc = cmdCode[k];
            W(cmdLen[cc], cmdCd[cc]);
            int ic = CellIns[cc >> 6] + ((cc >> 3) & 7), cpc = CellCopy[cc >> 6] + (cc & 7);
            W(InsExtra[ic], ins - InsBase[ic]);
            if (copy >= 2) W(CopyExtra[cpc], copy - CopyBase[cpc]); else W(CopyExtra[cpc], 0);
            St[EEmit] += 8;
            for (int i = 0; i < ins; i++)
            {
                int p = pos + i;
                int p1 = p >= 1 ? d[p - 1] : 0, p2 = p >= 2 ? d[p - 2] : 0;
                int t = cmap[BrotliData.ContextLut[mode * 512 + p1] | BrotliData.ContextLut[mode * 512 + 256 + p2]];
                W(litLen[t][d[p]], litCode[t][d[p]]);
            }
            St[EEmit] += 5L * ins; // AL : context, tree, code / length lookups, accumulator update
            if (dCode[k] >= 0)
            {
                W(distLen[dCode[k]], distCd[dCode[k]]);
                W(dExtraBits[k], dExtra[k]);
                St[EEmit] += 4;
            }
            pos += ins + copy;
        }
        // ---------------------------------------------------------------- incompressible : uncompressed meta-block instead
        if (BitPos() - (mark.len * 8L + mark.cnt) >= mlen * 8L + 32)
        {
            Rewind(mark);
            Rb = ringSave.Item1; RbIdx = ringSave.Item2;
            W(1, 0);
            int nib2 = mlen - 1 < (1 << 16) ? 4 : mlen - 1 < (1 << 20) ? 5 : 6;
            W(2, nib2 - 4); W(nib2 * 4, mlen - 1);
            W(1, 1); // ISUNCOMPRESSED
            WAlign();
            Out.Append(d, start, mlen);
            EncAppends++;
            // distances of this range are not in the ring any more : replay what the decoder sees (nothing)
        }
        _ = st0;
    }

    int ChooseMode(byte[] d, int start, int c0, int c1)
    {
        // sampled estimate : every 4th literal, per-context entropy + a tree cost per used context
        var h = new int[4, 64, 256];
        int pos = start;
        long samples = 0;
        for (int k = c0; k < c1; k++)
        {
            int ins = CIns[k];
            for (int i = 0; i < ins; i += 4)
            {
                int p = pos + i;
                int p1 = p >= 1 ? d[p - 1] : 0, p2 = p >= 2 ? d[p - 2] : 0;
                for (int m = 0; m < 4; m++) h[m, BrotliData.ContextLut[m * 512 + p1] | BrotliData.ContextLut[m * 512 + 256 + p2], d[p]]++;
                samples++;
            }
            pos += ins + CCopy[k];
        }
        St[ECtx] += samples * 6;
        int best = 0; double bestBits = double.MaxValue;
        for (int m = 0; m < 4; m++)
        {
            double bits = 0;
            for (int c = 0; c < 64; c++)
            {
                long n = 0; int used = 0;
                for (int s = 0; s < 256; s++) if (h[m, c, s] > 0) { n += h[m, c, s]; used++; }
                if (n == 0) continue;
                bits += 30 + 4 * used; // tree cost, scaled to the sample
                for (int s = 0; s < 256; s++) if (h[m, c, s] > 0) bits -= h[m, c, s] * Math.Log2((double)h[m, c, s] / n);
            }
            St[ECtx] += 64 * 256 * 3;
            if (bits < bestBits) { bestBits = bits; best = m; }
        }
        return best;
    }

    static double HCost(int[] h)
    {
        long n = 0; int used = 0;
        foreach (var x in h) if (x > 0) { n += x; used++; }
        if (n == 0) return 0;
        double bits = 16 + 4.5 * used;
        foreach (var x in h) if (x > 0) bits -= x * Math.Log2((double)x / n);
        return bits;
    }

    int[] Cluster(int[][] hist, out int nTrees, out List<int[]> treeHist)
    {
        // greedy pair merge while it saves bits ; AL : 256-symbol loops per pair evaluation
        var members = new List<List<int>>(); var cl = new List<int[]>(); var cost = new List<double>();
        for (int c = 0; c < 64; c++)
            if (hist[c].Any(v => v > 0)) { members.Add(new List<int> { c }); cl.Add((int[])hist[c].Clone()); cost.Add(HCost(hist[c])); }
        if (cl.Count == 0) { members.Add(new List<int> { 0 }); cl.Add(new int[256]); cost.Add(0); }
        St[ECluster] += 64 * 256 * 2;
        int n0 = cl.Count;
        // pair deltas, recomputed only for pairs touching a merged cluster
        var delta = new Dictionary<(int, int), double>();
        double PairDelta(int a, int b)
        {
            var m = new int[256];
            for (int s = 0; s < 256; s++) m[s] = cl[a][s] + cl[b][s];
            St[ECluster] += 256 * 3;
            return HCost(m) - cost[a] - cost[b];
        }
        var alive = Enumerable.Repeat(true, cl.Count).ToList();
        for (int a = 0; a < cl.Count; a++) for (int b = a + 1; b < cl.Count; b++) delta[(a, b)] = PairDelta(a, b);
        while (true)
        {
            double bd = 0; int ba = -1, bb = -1;
            foreach (var kv in delta) if (kv.Value < bd) { bd = kv.Value; (ba, bb) = kv.Key; }
            St[ECluster] += delta.Count;
            if (ba < 0) break;
            for (int s = 0; s < 256; s++) cl[ba][s] += cl[bb][s];
            cost[ba] = HCost(cl[ba]);
            members[ba].AddRange(members[bb]);
            alive[bb] = false;
            foreach (var key in delta.Keys.Where(k => k.Item1 == bb || k.Item2 == bb || k.Item1 == ba || k.Item2 == ba).ToList()) delta.Remove(key);
            for (int o = 0; o < cl.Count; o++) if (alive[o] && o != ba) delta[(Math.Min(o, ba), Math.Max(o, ba))] = PairDelta(Math.Min(o, ba), Math.Max(o, ba));
        }
        var cmap = new int[64];
        treeHist = new List<int[]>();
        int t = 0;
        for (int i = 0; i < cl.Count; i++)
        {
            if (!alive[i]) continue;
            foreach (var c in members[i]) cmap[c] = t;
            treeHist.Add(cl[i]);
            t++;
        }
        nTrees = t;
        return cmap;
    }

    void WriteContextMap(int[] cmap, int nTrees)
    {
        // RLEMAX 0, one prefix code over the tree indices, no IMTF (encoder side kept simple)
        W(1, 0);
        var h = new int[nTrees];
        foreach (var v in cmap) h[v]++;
        var (len, code) = PrepareCode(h);
        WritePrefixCode(len, h, nTrees);
        foreach (var v in cmap) W(len[v], code[v]);
        W(1, 0); // IMTF
        St[EHuff] += 64 * 3;
    }

    // ---------------------------------------------------------------------------------------------------- prefix codes
    (int[] len, int[] code) BuildCode(int[] hist, int maxLen)
    {
        int n = hist.Length;
        var len = new int[n];
        var used = Enumerable.Range(0, n).Where(i => hist[i] > 0).ToList();
        St[EHuff] += 2L * n;
        if (used.Count == 0) { len[0] = 0; return (len, new int[n]); }
        if (used.Count == 1) return (len, new int[n]); // simple code, 0 bits
        var w = used.Select(i => (long)hist[i]).ToArray();
        while (true)
        {
            var pq = new PriorityQueue<int, (long, int)>();
            int m = used.Count;
            var parent = new int[2 * m]; var depth = new int[2 * m];
            for (int i = 0; i < m; i++) { pq.Enqueue(i, (w[i], 0)); parent[i] = -1; }
            int nodes = m;
            while (pq.Count > 1)
            {
                pq.TryDequeue(out int a, out var pa); pq.TryDequeue(out int b, out var pb);
                parent[a] = parent[b] = nodes; parent[nodes] = -1; depth[nodes] = 1 + Math.Max(pa.Item2, pb.Item2);
                pq.Enqueue(nodes, (pa.Item1 + pb.Item1, depth[nodes])); nodes++;
            }
            int mx = 0;
            for (int i = 0; i < m; i++) { int dd = 0, k = i; while (parent[k] >= 0) { k = parent[k]; dd++; } len[used[i]] = dd; mx = Math.Max(mx, dd); }
            St[EHuff] += 40L * m;
            if (mx <= maxLen) break;
            for (int i = 0; i < m; i++) w[i] = 1 + w[i] / 2;
        }
        return (len, CanonicalReversed(len));
    }

    /// <summary>Lengths + codes as they will be written : simple code (<= 4 used symbols, fixed length patterns) or Huffman.</summary>
    (int[] len, int[] code) PrepareCode(int[] hist)
    {
        int n = hist.Length;
        var used = Enumerable.Range(0, n).Where(i => hist[i] > 0).OrderByDescending(i => hist[i]).ThenBy(i => i).ToList();
        St[EHuff] += 2L * n;
        if (used.Count > 4) return BuildCode(hist, 15);
        var len = new int[n];
        if (used.Count == 2) { len[used[0]] = 1; len[used[1]] = 1; }
        if (used.Count == 3) { len[used[0]] = 1; len[used[1]] = 2; len[used[2]] = 2; }
        if (used.Count == 4)
        {
            long a = 2L * used.Sum(i => (long)hist[i]);
            long b = hist[used[0]] + 2L * hist[used[1]] + 3L * (hist[used[2]] + hist[used[3]]);
            if (b < a) { len[used[0]] = 1; len[used[1]] = 2; len[used[2]] = 3; len[used[3]] = 3; }
            else foreach (var i in used) len[i] = 2;
        }
        return (len, CanonicalReversed(len));
    }

    static int[] CanonicalReversed(int[] len)
    {
        int n = len.Length;
        var blCount = new int[16]; var next = new int[16];
        foreach (var l in len) if (l > 0) blCount[l]++;
        int code = 0;
        for (int b = 1; b < 16; b++) { next[b] = code; code = (code + blCount[b]) << 1; }
        var r = new int[n];
        for (int s = 0; s < n; s++)
            if (len[s] > 0) { int c = next[len[s]]++; r[s] = Reverse(c, len[s]); }
        return r;
    }
    static int Reverse(int c, int l) { int r = 0; for (int i = 0; i < l; i++) { r = (r << 1) | (c & 1); c >>= 1; } return r; }

    void WritePrefixCode(int[] len, int[] hist, int alphabet)
    {
        int alphaBits = 0;
        while ((1 << alphaBits) < alphabet) alphaBits++;
        var used = Enumerable.Range(0, alphabet).Where(i => hist[i] > 0).ToList();
        if (used.Count == 0) used.Add(0);
        if (used.Count <= 4)
        {
            // simple prefix code : symbols listed by increasing code length (the decoder sorts equal lengths)
            W(2, 1); W(2, used.Count - 1);
            var order = used.OrderBy(x => len[x]).ThenBy(x => x).ToList();
            foreach (var x in order) W(alphaBits, x);
            if (used.Count == 4) W(1, len[order[0]] == 1 ? 1 : 0);
            St[EHuff] += 20;
            return;
        }
        // complex : code lengths symbols (0..15 literal lengths, 17 = run of 3..10 zeros, never two 17 in a row)
        int last = alphabet - 1;
        while (last > 0 && len[last] == 0) last--;
        var syms = new List<(int sym, int extra)>();
        for (int i = 0; i <= last;)
        {
            if (len[i] == 0)
            {
                int run = 0;
                while (i + run <= last && len[i + run] == 0) run++;
                int r = run;
                bool prevWas17 = false;
                while (r > 0)
                {
                    if (r >= 3 && !prevWas17) { int k = Math.Min(10, r); syms.Add((17, k - 3)); r -= k; prevWas17 = true; }
                    else { syms.Add((0, 0)); r--; prevWas17 = false; }
                }
                i += run;
            }
            else { syms.Add((len[i], 0)); i++; }
        }
        var clHist = new int[18];
        foreach (var s in syms) clHist[s.sym]++;
        var (clLen, clCode) = BuildCode(clHist, 5);
        int nonzero = clLen.Count(l => l > 0);
        if (clHist.Count(x => x > 0) == 1) { int only = Array.FindIndex(clHist, x => x > 0); clLen[only] = 1; nonzero = 1; clCode = new int[18]; }
        W(2, 0); // HSKIP 0
        int space = 32, written = 0;
        for (int i = 0; i < 18; i++)
        {
            int l = clLen[ClOrder[i]];
            // fixed code for code length code lengths (value -> bits, LSB first)
            switch (l)
            {
                case 0: W(2, 0); break;
                case 1: W(4, 7); break;
                case 2: W(3, 3); break;
                case 3: W(2, 2); break;
                case 4: W(2, 1); break;
                case 5: W(4, 15); break;
            }
            written++;
            if (l > 0) { space -= 32 >> l; if (space <= 0) break; }
        }
        bool single = nonzero == 1;
        foreach (var s in syms)
        {
            if (!single) W(clLen[s.sym], clCode[s.sym]);
            if (s.sym == 17) W(3, s.extra);
        }
        St[EHuff] += 10L * syms.Count + 60;
    }


    // ================================================================================================= decoder
    byte[] In; int InPos; ulong RAcc; int RCnt;
    void Refill() { while (RCnt <= 48) { RAcc |= (ulong)(InPos < In.Length ? In[InPos] : 0) << RCnt; InPos++; RCnt += 8; } }
    int R(int n) { if (n == 0) return 0; if (RCnt < n) Refill(); int v = (int)(RAcc & ((1UL << n) - 1)); RAcc >>= n; RCnt -= n; return v; }
    void RAlign() { int k = RCnt & 7; R(k); }

    sealed class Huff { public int[] Len; public int[] Val; public int Root = 8; }

    Huff BuildTable(int[] lens)
    {
        int n = lens.Length, maxL = 0;
        foreach (var l in lens) maxL = Math.Max(maxL, l);
        var h = new Huff();
        int used = lens.Count(l => l > 0);
        if (used == 1 && false) { }
        // canonical codes, reversed ; root 8 bits, sub tables for longer codes
        var codes = CanonicalReversed(lens);
        var subBits = new int[256];
        for (int s = 0; s < n; s++) if (lens[s] > 8) { int r = codes[s] & 255; subBits[r] = Math.Max(subBits[r], lens[s] - 8); }
        int total = 256;
        var subOff = new int[256];
        for (int r = 0; r < 256; r++) if (subBits[r] > 0) { subOff[r] = total; total += 1 << subBits[r]; }
        h.Len = new int[total]; h.Val = new int[total];
        for (int r = 0; r < 256; r++) if (subBits[r] > 0) { h.Len[r] = 100 + subBits[r]; h.Val[r] = subOff[r]; }
        for (int s = 0; s < n; s++)
        {
            int l = lens[s];
            if (l == 0) continue;
            int c = codes[s];
            if (l <= 8) for (int k = c; k < 256; k += 1 << l) { h.Len[k] = l; h.Val[k] = s; }
            else
            {
                int r = c & 255, sb = subBits[r];
                for (int k = c >> 8; k < 1 << sb; k += 1 << (l - 8)) { h.Len[subOff[r] + k] = l; h.Val[subOff[r] + k] = s; }
            }
        }
        if (used == 1) { int s0 = Array.FindIndex(lens, l => l > 0); for (int k = 0; k < 256; k++) { h.Len[k] = 0; h.Val[k] = s0; } }
        St[DHdr] += total + 3L * n;
        return h;
    }

    int Sym(Huff h, int stage)
    {
        if (RCnt < 15) Refill();
        int k = (int)(RAcc & 255);
        int l = h.Len[k], v = h.Val[k];
        if (l > 100)
        {
            int sb = l - 100;
            int k2 = v + (int)((RAcc >> 8) & ((1UL << sb) - 1));
            l = h.Len[k2]; v = h.Val[k2];
            St[stage] += 2;
        }
        RAcc >>= l; RCnt -= l;
        St[stage] += 5; // refill test, peek, 2 lookups, consume (AL : BitAcc div Pow2[L] ; BitCnt -= L)
        return v;
    }

    Huff ReadPrefixCode(int alphabet)
    {
        int alphaBits = 0;
        while ((1 << alphaBits) < alphabet) alphaBits++;
        var lens = new int[alphabet];
        int hskip = R(2);
        if (hskip == 1)
        {
            int nsym = R(2) + 1;
            var s = new int[nsym];
            for (int i = 0; i < nsym; i++) s[i] = R(alphaBits);
            int[] l = nsym switch { 1 => new[] { 0 }, 2 => new[] { 1, 1 }, 3 => new[] { 1, 2, 2 }, _ => R(1) == 1 ? new[] { 1, 2, 3, 3 } : new[] { 2, 2, 2, 2 } };
            if (nsym == 1) { lens[s[0]] = 1; var h1 = BuildTable(lens); return h1; }
            for (int i = 0; i < nsym; i++) lens[s[i]] = l[i];
            return BuildTable(lens);
        }
        // complex
        var clLens = new int[18];
        int space = 32, num = 0;
        for (int i = hskip; i < 18; i++)
        {
            if (RCnt < 4) Refill();
            int peek = (int)(RAcc & 15);
            int[] plen = { 2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4 };
            int[] pval = { 0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5 };
            int v = pval[peek]; R(plen[peek]);
            clLens[ClOrder[i]] = v;
            if (v != 0) { space -= 32 >> v; num++; if (space <= 0) break; }
        }
        if (!(num == 1 || space == 0)) throw new Exception("bad code length code");
        var clTbl = BuildTable(clLens);
        int sym = 0, prevLen = 8, repeat = 0, repeatLen = 0, space2 = 32768;
        while (sym < alphabet && space2 > 0)
        {
            int c = Sym(clTbl, DHdr);
            if (c < 16)
            {
                repeat = 0;
                lens[sym++] = c;
                if (c != 0) { prevLen = c; space2 -= 32768 >> c; }
            }
            else
            {
                int extraBits = c == 16 ? 2 : 3;
                int newLen = c == 16 ? prevLen : 0;
                if (repeatLen != newLen) { repeat = 0; repeatLen = newLen; }
                int old = repeat;
                if (repeat > 0) { repeat -= 2; repeat <<= extraBits; }
                repeat += R(extraBits) + 3;
                int cnt = repeat - old;
                if (sym + cnt > alphabet) throw new Exception("bad repeat");
                for (int k = 0; k < cnt; k++) lens[sym++] = repeatLen;
                if (repeatLen != 0) space2 -= cnt * (32768 >> repeatLen);
            }
        }
        if (space2 != 0) throw new Exception("bad prefix code space");
        return BuildTable(lens);
    }

    int ReadVarLen() { if (R(1) == 0) return 0; int n = R(3); if (n == 0) return 1; return (1 << n) + R(n); }

    int[] ReadContextMap(int size, int nTrees)
    {
        var map = new int[size];
        if (nTrees == 1) return map;
        int rleMax = R(1) == 1 ? R(4) + 1 : 0;
        var h = ReadPrefixCode(nTrees + rleMax);
        for (int i = 0; i < size;)
        {
            int c = Sym(h, DHdr);
            if (c == 0) map[i++] = 0;
            else if (c <= rleMax) { int run = (1 << c) + R(c); for (int k = 0; k < run; k++) map[i++] = 0; }
            else map[i++] = c - rleMax;
        }
        if (R(1) == 1)
        {
            var mtf = Enumerable.Range(0, 256).ToArray();
            for (int i = 0; i < size; i++)
            {
                int idx = map[i], v = mtf[idx];
                map[i] = v;
                for (int k = idx; k > 0; k--) mtf[k] = mtf[k - 1];
                mtf[0] = v;
            }
        }
        St[DHdr] += 4L * size;
        return map;
    }

    sealed class BlockState { public int N = 1; public Huff TypeCode, LenCode; public int Type, Prev = 1, Len = 1 << 28; }

    BlockState ReadBlockState()
    {
        var b = new BlockState { N = ReadVarLen() + 1 };
        if (b.N >= 2)
        {
            b.TypeCode = ReadPrefixCode(b.N + 2);
            b.LenCode = ReadPrefixCode(26);
            b.Len = ReadBlockLen(b.LenCode);
            b.Type = 0; b.Prev = 1;
        }
        return b;
    }
    int ReadBlockLen(Huff h) { int c = Sym(h, DHdr); return BlkBase[c] + R(BlkExtra[c]); }
    void Switch(BlockState b)
    {
        int c = Sym(b.TypeCode, DHdr);
        int t = c == 0 ? b.Prev : c == 1 ? (b.Type + 1) % b.N : c - 2;
        if (t >= b.N) t -= b.N;
        b.Prev = b.Type; b.Type = t; BlockSwitches++;
        b.Len = ReadBlockLen(b.LenCode);
        St[DHdr] += 6;
    }

    public byte[] Decompress(byte[] input)
    {
        In = input; InPos = 0; RAcc = 0; RCnt = 0;
        int wbits;
        if (R(1) == 0) wbits = 16;
        else { int n = R(3); if (n != 0) wbits = 17 + n; else { n = R(3); wbits = n == 1 ? throw new Exception("large window") : n != 0 ? 8 + n : 17; } }
        int maxBack = (1 << wbits) - 16;
        var outB = new List<byte>(input.Length * 4);
        var rb = new[] { 16, 15, 11, 4 }; int rbi = 0; // ring : last = rb[(rbi + 3) & 3]
        while (true)
        {
            int isLast = R(1);
            if (isLast == 1 && R(1) == 1) break;
            int mnib = R(2);
            int mlen;
            if (mnib == 3)
            {
                if (R(1) != 0) throw new Exception("reserved");
                int skipBytes = R(2);
                int skip = 0;
                for (int i = 0; i < skipBytes; i++) skip |= R(8) << (8 * i);
                if (skipBytes > 0) skip++;
                RAlign();
                for (int i = 0; i < skip; i++) R(8);
                if (isLast == 1) break;
                continue;
            }
            mnib += 4;
            mlen = 0;
            for (int i = 0; i < mnib; i++) mlen |= R(4) << (4 * i);
            mlen++;
            if (isLast == 0 && R(1) == 1)
            {
                RAlign();
                for (int i = 0; i < mlen; i++) outB.Add((byte)R(8));
                St[DCopy] += 4; TextOps++;
                continue;
            }
            var bl = ReadBlockState(); var bi = ReadBlockState(); var bd = ReadBlockState();
            int npostfix = R(2), ndirect = R(4) << npostfix;
            var modes = new int[bl.N];
            for (int i = 0; i < bl.N; i++) modes[i] = R(2);
            int ntreesL = ReadVarLen() + 1;
            var cmapL = ReadContextMap(64 * bl.N, ntreesL);
            int ntreesD = ReadVarLen() + 1;
            var cmapD = ReadContextMap(4 * bd.N, ntreesD);
            var litT = new Huff[ntreesL];
            for (int t = 0; t < ntreesL; t++) litT[t] = ReadPrefixCode(256);
            var cmdT = new Huff[bi.N];
            for (int t = 0; t < bi.N; t++) cmdT[t] = ReadPrefixCode(704);
            int distAlpha = 16 + ndirect + (48 << npostfix);
            var distT = new Huff[ntreesD];
            for (int t = 0; t < ntreesD; t++) distT[t] = ReadPrefixCode(distAlpha);
            St[DHdr] += 60;
            bool multiL = bl.N > 1;
            int end = outB.Count + mlen;
            while (outB.Count < end)
            {
                if (bi.N > 1) { if (bi.Len == 0) Switch(bi); bi.Len--; St[DCmd] += 2; }
                int cmd = Sym(cmdT[bi.Type], DCmd);
                int cell = cmd >> 6;
                int ic = CellIns[cell] + ((cmd >> 3) & 7), cc = CellCopy[cell] + (cmd & 7);
                int ins = InsBase[ic] + R(InsExtra[ic]);
                int copy = CopyBase[cc] + R(CopyExtra[cc]);
                St[DCmd] += 7; // cell / code lookups (2), 2 x (extra bits read + add), loop test
                // literals
                int mode = modes[bl.Type];
                for (int i = 0; i < ins; i++)
                {
                    if (multiL) { if (bl.Len == 0) { Switch(bl); mode = modes[bl.Type]; } bl.Len--; St[DLit] += 2; }
                    int n = outB.Count;
                    int p1 = n >= 1 ? outB[n - 1] : 0, p2 = n >= 2 ? outB[n - 2] : 0;
                    int ctx = BrotliData.ContextLut[mode * 512 + p1] | BrotliData.ContextLut[mode * 512 + 256 + p2];
                    int lit = Sym(litT[cmapL[bl.Type * 64 + ctx]], DLit);
                    outB.Add((byte)lit);
                    St[DLit] += 5; // for step, tree := CMap[...] (context in the index), P2 := P1, P1 := Lit, pair assembly
                    DecAppends++; // counted per literal ; halved below (2 literals per append)
                    if (outB.Count == end) break;
                }
                if (outB.Count >= end) break;
                // distance
                int dist, dcode;
                if (cell < 2) { dcode = 0; dist = rb[(rbi + 3) & 3]; }
                else
                {
                    if (bd.N > 1) { if (bd.Len == 0) Switch(bd); bd.Len--; St[DDist] += 2; }
                    int dctx = copy > 4 ? 3 : copy - 2;
                    dcode = Sym(distT[cmapD[bd.Type * 4 + dctx]], DDist);
                    St[DDist] += 2;
                    if (dcode < 16)
                    {
                        int last = rb[(rbi + 3) & 3], second = rb[(rbi + 2) & 3];
                        dist = dcode switch
                        {
                            0 => last, 1 => second, 2 => rb[(rbi + 1) & 3], 3 => rb[rbi & 3],
                            4 => last - 1, 5 => last + 1, 6 => last - 2, 7 => last + 2, 8 => last - 3, 9 => last + 3,
                            10 => second - 1, 11 => second + 1, 12 => second - 2, 13 => second + 2, 14 => second - 3, _ => second + 3,
                        };
                        if (dist <= 0) throw new Exception("bad distance");
                        St[DDist] += 3;
                    }
                    else if (dcode < 16 + ndirect) { dist = dcode - 15; St[DDist] += 2; }
                    else
                    {
                        int x = dcode - ndirect - 16;
                        int ndb = 1 + (x >> (npostfix + 1));
                        int hc = x >> npostfix, lc = x & ((1 << npostfix) - 1);
                        int off = ((2 + (hc & 1)) << ndb) - 4;
                        dist = ((off + R(ndb)) << npostfix) + lc + ndirect + 1;
                        St[DDist] += 5;
                    }
                }
                int maxDist = Math.Min(maxBack, outB.Count);
                if (dist > maxDist)
                {
                    // static dictionary word
                    if (copy < 4 || copy > 24) throw new Exception("bad dictionary copy");
                    int wordId = dist - maxDist - 1;
                    int nb = NDBits[copy];
                    int idx = wordId & ((1 << nb) - 1), tr = wordId >> nb;
                    if (tr >= 121) throw new Exception("bad transform");
                    var word = Transform(Dict.AsSpan(DOffset[copy] + idx * copy, copy), tr);
                    outB.AddRange(word); DictRefs++;
                    St[DCopy] += 12; TextOps += 3;
                }
                else
                {
                    if (dcode != 0) { rb[rbi] = dist; rbi = (rbi + 1) & 3; St[DDist] += 2; }
                    int from = outB.Count - dist;
                    for (int k = 0; k < copy; k++) outB.Add(outB[from + k]);
                    // AL : ToText(from, len) + Append (+ a loop of pattern appends when dist < copy), P1 / P2 from the copied text
                    St[DCopy] += 5; TextOps += dist < copy ? 2 + (copy / Math.Max(dist, 1) > 1 ? 2 : 0) : 2;
                }
            }
            if (outB.Count > end) throw new Exception("meta-block overrun");
            if (isLast == 1) break;
        }
        return outB.ToArray();
    }

    static byte[] Transform(ReadOnlySpan<byte> word, int id)
    {
        var (pre, type, suf) = BrotliData.Transforms[id];
        var w = word.ToArray().ToList();
        if (type >= 1 && type <= 9) w.RemoveRange(Math.Max(0, w.Count - type), Math.Min(type, w.Count));
        else if (type >= 12 && type <= 20) w.RemoveRange(0, Math.Min(type - 11, w.Count));
        var arr = w.ToArray();
        if (type == 10) Upper(arr, 0);
        else if (type == 11) for (int i = 0; i < arr.Length;) i += Upper(arr, i);
        var r = new List<byte>();
        r.AddRange(pre.Select(c => (byte)c)); r.AddRange(arr); r.AddRange(suf.Select(c => (byte)c));
        return r.ToArray();
    }

    static int Upper(byte[] p, int i)
    {
        if (p[i] < 0xC0) { if (p[i] >= 'a' && p[i] <= 'z') p[i] ^= 32; return 1; }
        if (p[i] < 0xE0) { if (i + 1 < p.Length) p[i + 1] ^= 32; return 2; }
        if (i + 2 < p.Length) p[i + 2] ^= 5;
        return 3;
    }
}
