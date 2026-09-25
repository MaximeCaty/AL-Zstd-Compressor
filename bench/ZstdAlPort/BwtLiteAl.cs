namespace ZstdAlPort;

/*
    BWT-lite : own block format designed for a fast pure-AL decoder, written the AL way (1 counted statement = 1 AL
    statement, if / while test or for step included) to estimate its AL speed ; round trip checked by the bench.

    Block (<= BlockMax bytes, arrays <= 1M elements) :
      n (24 bits), primary row (24), histogram flag (1) [+ used-byte map + gamma counts], symbol map, nGroups (3),
      nSelectors (15), selectors (MTF unary), Huffman tables (delta lengths), symbols (MSB-first).
    Transform : sentinel BWT (plain SA-IS suffix array, no rotation search, no RLE1, no CRC).
    Symbols over the BWT column : same byte as the previous one -> run (RUNA / RUNB digits) ; byte at rank r (1..K-1) in a
    K-entry recency list (bounded move-to-front) -> symbol 1 + r ; other byte -> literal K + 1 + byte ; EOB.
    bzip2 multi-table Huffman (2..6 tables, selectors per 50 symbols, NIters passes), code lengths <= MaxCodeLen.

    Decoder (per output byte, the design choices that make it cheap in AL) :
    - with the histogram, the bucket starts Cf are known before decoding : the Next vector is filled while decoding, a run
      of R bytes with ONE statement per byte (for J := Cf to Cf + R - 1 do Next[J] := J + Delta), a literal / rank byte
      with 3 ; small blocks (no histogram) decode into L first, then build Next (2 statements per byte) ;
    - the first column F is 256 PadRight appends (bulk), the walk emits 2 bytes per Append(PairTbl[...]) with 4
      statements : P := Next[P]; A := F[P]; P := Next[P]; Append(PairTbl[A + F[P] * 256 + 1]) ;
    - Huffman symbols decoded with a 2^maxLen lookup per table.
*/
public sealed class BwtLiteAl
{
    public const int ESa = 0, EBwt = 1, EMtf = 2, EHuf = 3, EEmit = 4, DTbl = 5, DHuf = 6, DMtf = 7, DFill = 8, DWalk = 9;
    public static readonly string[] StageNames = { "SA-IS", "BWT column", "runs + recency", "Huffman tables", "bit output",
        "decode tables", "Huffman decode", "runs + recency", "Next fill", "walk + output" };
    public readonly long[] St = new long[10];
    public long EncAppends, DecAppends;
    public int K = 16, NIters = 2, MaxCodeLen = 17, BlockMax = 999000, HistMin = 65536;

    // ================================================================================================= bit I/O
    ByteBuilder Out; long BwAcc; int BwCnt;
    void BsW(int n, long v)
    {
        BwAcc = BwAcc * (1L << n) + v; BwCnt += n;
        while (BwCnt >= 16)
        {
            long pair = BwAcc >> (BwCnt - 16);
            Out.Append((byte)(pair >> 8)); Out.Append((byte)pair);
            BwAcc &= (1L << (BwCnt - 16)) - 1; BwCnt -= 16;
            St[EEmit] += 4; EncAppends++;
        }
    }
    void BsFlush()
    {
        while (BwCnt >= 8) { Out.Append((byte)(BwAcc >> (BwCnt - 8))); BwCnt -= 8; BwAcc &= (1L << BwCnt) - 1; }
        if (BwCnt > 0) { Out.Append((byte)(BwAcc << (8 - BwCnt))); BwCnt = 0; BwAcc = 0; }
    }
    void Gamma(long v) { int b = 63 - System.Numerics.BitOperations.LeadingZeroCount((ulong)v); for (int i = 0; i < b; i++) BsW(1, 0); BsW(b + 1, v); }

    byte[] In; int InPos; long BrAcc; int BrCnt;
    int BsR(int n)
    {
        while (BrCnt < n) { BrAcc = (BrAcc << 8) | (InPos < In.Length ? In[InPos] : 0); InPos++; BrCnt += 8; }
        int v = (int)(BrAcc >> (BrCnt - n)) & (int)((1L << n) - 1);
        BrCnt -= n; BrAcc &= (1L << BrCnt) - 1;
        return v;
    }
    long GammaR() { int b = 0; while (BsR(1) == 0) b++; long v = 1; for (int i = 0; i < b; i++) v = v * 2 + BsR(1); return v; }

    // ================================================================================================= encoder
    public byte[] Compress(byte[] input)
    {
        Out = new ByteBuilder(); BwAcc = 0; BwCnt = 0;
        BsW(32, 0x42574C31); // "BWL1"
        BsW(32, input.Length);
        for (int off = 0; off < input.Length; off += BlockMax)
            CompressBlock(input, off, Math.Min(BlockMax, input.Length - off));
        BsFlush();
        return Out.ToArray();
    }

    void CompressBlock(byte[] d, int off, int n)
    {
        // --- suffix array (AL : s read from InText chars, sentinel appended)
        var s = new int[n + 1];
        for (int i = 0; i < n; i++) s[i] = d[off + i] + 1;
        var sais = new Bz2Al();
        var sa = new int[n + 1];
        sais.SuffixArray(s, sa, 257);
        St[ESa] += sais.St[Bz2Al.SSais];
        // --- BWT column without the sentinel, primary = row of the whole string
        var L = new int[n];
        int primary = 0, o = 0;
        for (int r = 0; r <= n; r++)
        {
            int p = sa[r];
            if (p == 0) primary = r; else L[o++] = d[off + p - 1];
            St[EBwt] += 4;
        }
        // --- runs + bounded move-to-front (K-entry recency list)
        var syms = new List<int>(n / 2);
        var rec = new int[K];
        for (int i = 0; i < K; i++) rec[i] = -1;
        var hist = new int[256];
        int run = 0;
        for (int x = 0; x < n; x++)
        {
            int c = L[x];
            St[EMtf] += 3; // for step, c, run test
            if (rec[0] == c) { run++; St[EMtf]++; continue; }
            if (run > 0) { PutRun(syms, run); run = 0; }
            int j = 1;
            while (j < K && rec[j] != c) j++;
            St[EMtf] += 2L * j; // AL : Rec.IndexOf on a K-char Text would be 1 statement ; counted as a loop
            if (j < K) syms.Add(1 + j); else { syms.Add(K + 1 + c); j = K - 1; }
            for (int z = j; z > 0; z--) rec[z] = rec[z - 1];
            rec[0] = c;
            St[EMtf] += 2L * j + 4;
        }
        if (run > 0) PutRun(syms, run);
        for (int x = 0; x < n; x++) hist[L[x]]++;
        int EOB = K + 257;
        syms.Add(EOB);
        // alphabet compaction : two-level map over the K + 258 symbols (16-symbol groups)
        int full = K + 258, nGrp16 = (full + 15) / 16;
        var used = new bool[full];
        foreach (var y in syms) used[y] = true;
        var toC = new int[full];
        int alpha = 0;
        for (int y = 0; y < full; y++) if (used[y]) toC[y] = alpha++;
        var mtfv = new int[syms.Count];
        for (int y = 0; y < syms.Count; y++) mtfv[y] = toC[syms[y]];
        St[EMtf] += syms.Count;

        // --- header
        BsW(24, n); BsW(24, primary);
        bool withHist = n >= HistMin;
        BsW(1, withHist ? 1 : 0);
        if (withHist)
        {
            // used-byte map (16 + 16 per used group) then gamma(count) per used byte
            var u16 = new bool[16];
            for (int b = 0; b < 256; b++) if (hist[b] > 0) u16[b / 16] = true;
            for (int g = 0; g < 16; g++) BsW(1, u16[g] ? 1 : 0);
            for (int g = 0; g < 16; g++) if (u16[g]) for (int b = g * 16; b < g * 16 + 16; b++) BsW(1, hist[b] > 0 ? 1 : 0);
            for (int b = 0; b < 256; b++) if (hist[b] > 0) Gamma(hist[b]);
        }
        {
            var ug = new bool[nGrp16];
            for (int y = 0; y < full; y++) if (used[y]) ug[y / 16] = true;
            for (int g = 0; g < nGrp16; g++) BsW(1, ug[g] ? 1 : 0);
            for (int g = 0; g < nGrp16; g++) if (ug[g]) for (int y = g * 16; y < g * 16 + 16; y++) BsW(1, y < full && used[y] ? 1 : 0);
        }
        HuffmanBlock(mtfv, alpha);
    }

    void PutRun(List<int> syms, int run)
    {
        int z = run - 1;
        St[EMtf] += 2;
        while (true) { syms.Add((z & 1) != 0 ? 1 : 0); St[EMtf] += 4; if (z < 2) break; z = (z - 2) / 2; }
    }

    void HuffmanBlock(int[] mtfv, int alphaSize)
    {
        int nMTF = mtfv.Length;
        var mtfFreq = new int[alphaSize];
        foreach (var x in mtfv) mtfFreq[x]++;
        int nGroups = nMTF < 200 ? 2 : nMTF < 600 ? 3 : nMTF < 1200 ? 4 : nMTF < 2400 ? 5 : 6;
        var len = new int[nGroups, alphaSize];
        {
            int nPart = nGroups, remF = nMTF, gs = 0;
            while (nPart > 0)
            {
                int tFreq = remF / nPart, ge = gs - 1, aFreq = 0;
                while (aFreq < tFreq && ge < alphaSize - 1) { ge++; aFreq += mtfFreq[ge]; }
                if (ge > gs && nPart != nGroups && nPart != 1 && ((nGroups - nPart) % 2 == 1)) { aFreq -= mtfFreq[ge]; ge--; }
                for (int v = 0; v < alphaSize; v++) len[nPart - 1, v] = (v >= gs && v <= ge) ? 0 : 15;
                nPart--; gs = ge + 1; remF -= aFreq;
            }
        }
        int nSelectors = (nMTF + 49) / 50;
        var selector = new int[nSelectors];
        var cost = new int[6];
        for (int iter = 0; iter < NIters; iter++)
        {
            var rfreq = new int[nGroups, alphaSize];
            int gs = 0, nSel = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1);
                for (int t = 0; t < nGroups; t++) cost[t] = 0;
                for (int x = gs; x <= ge; x++) for (int t = 0; t < nGroups; t++) cost[t] += len[t, mtfv[x]];
                int bt = 0;
                for (int t = 1; t < nGroups; t++) if (cost[t] < cost[bt]) bt = t;
                selector[nSel++] = bt;
                for (int x = gs; x <= ge; x++) rfreq[bt, mtfv[x]]++;
                St[EHuf] += (ge - gs + 1) * (4L + nGroups) + 4 + 2 * nGroups;
                gs = ge + 1;
            }
            for (int t = 0; t < nGroups; t++) { MakeLengths(len, rfreq, t, alphaSize, MaxCodeLen); St[EHuf] += 40L * alphaSize; }
        }
        var code = new int[nGroups, alphaSize];
        for (int t = 0; t < nGroups; t++)
        {
            int minL = 32, maxL = 0;
            for (int v = 0; v < alphaSize; v++) { minL = Math.Min(minL, len[t, v]); maxL = Math.Max(maxL, len[t, v]); }
            int vec = 0;
            for (int L2 = minL; L2 <= maxL; L2++) { for (int v = 0; v < alphaSize; v++) if (len[t, v] == L2) code[t, v] = vec++; vec <<= 1; }
        }
        BsW(3, nGroups); BsW(15, nSelectors);
        var pos = new int[6];
        for (int t = 0; t < nGroups; t++) pos[t] = t;
        foreach (var v0 in selector)
        {
            int j = Array.IndexOf(pos, v0);
            for (int k = j; k > 0; k--) pos[k] = pos[k - 1];
            pos[0] = v0;
            for (int y = 0; y < j; y++) BsW(1, 1);
            BsW(1, 0);
        }
        for (int t = 0; t < nGroups; t++)
        {
            int curr = len[t, 0];
            BsW(5, curr);
            for (int v = 0; v < alphaSize; v++)
            {
                while (curr < len[t, v]) { BsW(2, 2); curr++; }
                while (curr > len[t, v]) { BsW(2, 3); curr--; }
                BsW(1, 0);
            }
        }
        {
            int sc = 0, gs = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1), t = selector[sc++];
                for (int x = gs; x <= ge; x++) { BsW(len[t, mtfv[x]], code[t, mtfv[x]]); St[EEmit] += 4; }
                gs = ge + 1;
            }
        }
    }

    static void MakeLengths(int[,] len, int[,] freq, int t, int alphaSize, int maxLen)
    {
        var w = new long[alphaSize];
        for (int i = 0; i < alphaSize; i++) w[i] = Math.Max(1, freq[t, i]);
        while (true)
        {
            var pq = new PriorityQueue<int, (long, int)>();
            int nodes = alphaSize;
            var parent = new int[2 * alphaSize];
            var depth = new int[2 * alphaSize];
            var wt = new long[2 * alphaSize];
            for (int i = 0; i < alphaSize; i++) { pq.Enqueue(i, (w[i], 0)); parent[i] = -1; wt[i] = w[i]; }
            if (alphaSize == 1) { len[t, 0] = 1; return; }
            while (pq.Count > 1)
            {
                pq.TryDequeue(out int a, out var pa); pq.TryDequeue(out int b, out var pb);
                parent[a] = parent[b] = nodes; parent[nodes] = -1;
                wt[nodes] = pa.Item1 + pb.Item1; depth[nodes] = 1 + Math.Max(pa.Item2, pb.Item2);
                pq.Enqueue(nodes, (wt[nodes], depth[nodes])); nodes++;
            }
            int mx = 0;
            for (int i = 0; i < alphaSize; i++) { int dd = 0, k = i; while (parent[k] >= 0) { k = parent[k]; dd++; } len[t, i] = Math.Max(1, dd); mx = Math.Max(mx, dd); }
            if (mx <= maxLen) return;
            for (int i = 0; i < alphaSize; i++) w[i] = 1 + w[i] / 2;
        }
    }

    // ================================================================================================= decoder
    public byte[] Decompress(byte[] input)
    {
        In = input; InPos = 0; BrAcc = 0; BrCnt = 0;
        if (BsR(16) != 0x4257 || BsR(16) != 0x4C31) throw new Exception("bad magic");
        int total = (BsR(16) << 16) | BsR(16);
        var outB = new ByteBuilder();
        var next = new int[BlockMax + 1];
        var L = new int[BlockMax + 1];
        while (outB.Length < total) DecodeBlock(outB, next, L);
        return outB.ToArray();
    }

    void DecodeBlock(ByteBuilder outB, int[] next, int[] Lbuf)
    {
        int n = BsR(24), primary = BsR(24);
        bool withHist = BsR(1) == 1;
        var cf = new int[257]; // Cf[c] = first F row of byte c (row 0 = sentinel)
        if (withHist)
        {
            var u16 = new bool[16];
            for (int g = 0; g < 16; g++) u16[g] = BsR(1) == 1;
            var usedB = new bool[256];
            for (int g = 0; g < 16; g++) if (u16[g]) for (int b = g * 16; b < g * 16 + 16; b++) usedB[b] = BsR(1) == 1;
            var h = new int[256];
            for (int b = 0; b < 256; b++) if (usedB[b]) h[b] = (int)GammaR();
            int acc = 1;
            for (int b = 0; b < 256; b++) { cf[b] = acc; acc += h[b]; }
            cf[256] = acc;
        }
        int full = K + 258, nGrp16 = (full + 15) / 16;
        var fromC = new int[full];
        int alpha = 0;
        {
            var ug = new bool[nGrp16];
            for (int g = 0; g < nGrp16; g++) ug[g] = BsR(1) == 1;
            for (int g = 0; g < nGrp16; g++) if (ug[g]) for (int y = g * 16; y < g * 16 + 16; y++) if (BsR(1) == 1 && y < full) fromC[alpha++] = y;
        }
        int nGroups = BsR(3), nSelectors = BsR(15);
        var selector = new int[nSelectors];
        var pos = new int[6];
        for (int t = 0; t < nGroups; t++) pos[t] = t;
        for (int x = 0; x < nSelectors; x++)
        {
            int j = 0; while (BsR(1) == 1) j++;
            int tmp = pos[j];
            for (int k = j; k > 0; k--) pos[k] = pos[k - 1];
            pos[0] = tmp; selector[x] = tmp;
        }
        var len = new int[nGroups, alpha];
        for (int t = 0; t < nGroups; t++)
        {
            int curr = BsR(5);
            for (int v = 0; v < alpha; v++) { while (BsR(1) == 1) curr += BsR(1) == 0 ? 1 : -1; len[t, v] = curr; }
        }
        var maxLen = new int[nGroups];
        var dSym = new int[nGroups][]; var dLen = new int[nGroups][];
        for (int t = 0; t < nGroups; t++)
        {
            int minL = 32, mx = 0;
            for (int v = 0; v < alpha; v++) { minL = Math.Min(minL, len[t, v]); mx = Math.Max(mx, len[t, v]); }
            maxLen[t] = mx; dSym[t] = new int[1 << mx]; dLen[t] = new int[1 << mx];
            int vec = 0;
            for (int L2 = minL; L2 <= mx; L2++)
            {
                for (int v = 0; v < alpha; v++)
                    if (len[t, v] == L2)
                    {
                        int first = vec << (mx - L2), cnt = 1 << (mx - L2);
                        for (int e = 0; e < cnt; e++) { dSym[t][first + e] = fromC[v]; dLen[t][first + e] = L2; }
                        St[DTbl] += 3L * cnt + 3;
                        vec++;
                    }
                vec <<= 1;
            }
            St[DTbl] += 2L * alpha * (mx - minL + 2);
        }

        // --- symbols -> Next (histogram) or L (no histogram)
        var rec = new int[K];
        for (int i = 0; i < K; i++) rec[i] = -1;
        int I = 0; // next L row (0..n, skipping the primary row = sentinel)
        int groupNo = -1, groupPos = 0, gT = 0, gMax = 0, es = 0, N = 1;
        int EOB = K + 257;
        if (I == primary) I++;
        while (true)
        {
            if (groupPos == 0) { groupNo++; groupPos = 50; gT = selector[groupNo]; gMax = maxLen[gT]; St[DHuf] += 4; }
            groupPos--;
            while (BrCnt < gMax) { BrAcc = (BrAcc << 8) | (InPos < In.Length ? In[InPos] : 0); InPos++; BrCnt += 8; St[DHuf] += 1; }
            int peek = (int)(BrAcc >> (BrCnt - gMax)) & ((1 << gMax) - 1);
            int sym = dSym[gT][peek];
            BrCnt -= dLen[gT][peek];
            BrAcc &= (1L << BrCnt) - 1;
            St[DHuf] += 7;
            if (sym <= 1) { es += (sym + 1) * N; N *= 2; St[DMtf] += 3; continue; }
            St[DMtf] += 1;
            if (es > 0)
            {
                // run of es copies of rec[0]
                int c = rec[0];
                if (withHist)
                {
                    // for J := Cf[c] to Cf[c] + R - 1 do Next[J] := J + Delta ; split at the primary row (rare)
                    int r = es;
                    while (r > 0)
                    {
                        int chunk = I <= primary && primary < I + r ? primary - I : r;
                        int delta = I - cf[c];
                        for (int j2 = cf[c]; j2 < cf[c] + chunk; j2++) next[j2] = j2 + delta;
                        cf[c] += chunk; I += chunk; r -= chunk;
                        if (I == primary) I++;
                        St[DFill] += chunk + 6;
                    }
                }
                else
                {
                    for (int e = 0; e < es; e++) { Lbuf[I] = c; I++; if (I == primary) I++; }
                    St[DFill] += es + 3; // AL : for loop Lbuf[J] := C (the primary row is skipped by splitting the loop)
                }
                es = 0; N = 1;
                St[DMtf] += 3;
            }
            if (sym == EOB) break;
            {
                int c, j;
                if (sym < K + 1) { j = sym - 1; c = rec[j]; } else { c = sym - K - 1; j = K - 1; }
                for (int z = j; z > 0; z--) rec[z] = rec[z - 1];
                rec[0] = c;
                St[DMtf] += 4 + 2L * j; // AL alternative : K-char Text recency list, 2 statements whatever the rank
                if (withHist) { next[cf[c]] = I; cf[c]++; I++; if (I == primary) I++; St[DFill] += 4; }
                else { Lbuf[I] = c; I++; if (I == primary) I++; St[DFill] += 3; }
            }
        }
        if (!withHist)
        {
            // histogram from L, then Next : Next[Cf[L[I]]] := I ; Cf[L[I]] += 1
            var h = new int[256];
            for (int i = 0; i <= n; i++) if (i != primary) h[Lbuf[i]]++;
            int acc = 1;
            for (int b = 0; b < 256; b++) { cf[b] = acc; acc += h[b]; }
            cf[256] = acc;
            var c2 = (int[])cf.Clone();
            for (int i = 0; i <= n; i++) if (i != primary) next[c2[Lbuf[i]]++] = i;
            St[DFill] += 4L * n;
        }
        // --- walk : F from the bucket starts (AL : 256 PadRight appends), 2 bytes per append
        var F = new byte[n + 1];
        {
            // bucket of byte b = rows [start_b, end_b) : rebuilt from the final Cf (Cf[b] = end of bucket b now)
            int start = 1;
            for (int b = 0; b < 256; b++)
            {
                // histogram path : Cf advanced to the bucket end ; else Cf = bucket start
                int end = withHist ? cf[b] : (b < 255 ? cf[b + 1] : n + 1);
                for (int r = start; r < end; r++) F[r] = (byte)b;
                start = end;
            }
            St[DWalk] += 256;
        }
        int p = primary;
        for (int k = 0; k < n; k++)
        {
            outB.Append(F[p]);
            p = next[p];
        }
        St[DWalk] += 2L * n; // 4 statements per 2 bytes
        DecAppends += (n + 1) / 2;
    }
}
