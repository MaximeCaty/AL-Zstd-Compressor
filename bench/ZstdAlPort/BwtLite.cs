namespace ZstdAlPort;

/*
    BWT-lite ratio experiments (`--bwtlite <file or dir>...`) : sizes only, exact bzip2-style multi-table Huffman sizes
    (tables + selectors + symbols) for several ways of coding a BWT, per 900 KB-class block (<= 1M array elements).
    Own format : sentinel BWT with a primary index (no rotation search, no RLE1, no CRC), no MTF.
    Variants :
      B8   byte BWT : run of the previous byte -> RUNA / RUNB (bijective base 2), else byte ; one multi-table stream.
      P16  pair BWT (16-bit symbols, n / 2 steps) : run of the previous pair -> RUNA / RUNB in the hi stream, else hi byte
           in the hi stream + lo byte in a second multi-table stream.
      P16c pair BWT, lo byte stream split by hi byte class (hi = previous symbol's hi : same-context tables).
      P16b best of alignment 0 / 1 per block (1 header bit ; 2 sorts at encode).
    Inverse-transform cost per output byte in AL (statements) : B8 ~ fill Next 3 + walk 2.5 ; P16 ~ (3 + 2) / 2.
*/
public static class BwtLite
{
    public static int Run(string[] args)
    {
        var files = args.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
        var zenc = new ZstdAlEncoder();
        string[] names = { "B8", "B8m2", "B8m4", "B8m8", "B8m16", "MTF" };
        var tot = new long[names.Length];
        long raw = 0, gzT = 0, zhT = 0;
        var symStats = new double[names.Length];
        Console.WriteLine($"{"file",-26}{"raw",11}" + string.Join("", names.Select(n => $"{n,9}")) + $"{"zstd-H",9}   (size vs gz-opt)   symbols / byte B8 B8m4");
        foreach (var f in files)
        {
            var d = File.ReadAllBytes(f);
            long gz = Gz(d), zh = zenc.Compress(d, ZstdLevel.Heavy).Length;
            var sz = new long[names.Length];
            long symB8 = 0, symP16 = 0;
            const int Block = 900000;
            for (int off = 0; off < d.Length; off += Block)
            {
                int n = Math.Min(Block, d.Length - off);
                var blk = new byte[n];
                Array.Copy(d, off, blk, 0, n);
                var v = new int[n];
                for (int i = 0; i < n; i++) v[i] = blk[i];
                var L = Bwt(v, 256);
                int[] ks = { 1, 2, 4, 8, 16, 256 };
                for (int i = 0; i < ks.Length; i++)
                {
                    var (b, sy) = SizeRecent(L, ks[i]);
                    sz[i] += b + 8;
                    if (i == 0) symB8 += sy;
                    if (i == 2) symP16 += sy;
                }
            }
            for (int i = 0; i < names.Length; i++) tot[i] += sz[i];
            raw += d.Length; gzT += gz; zhT += zh;
            Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,11}" + string.Join("", sz.Select(s => $"{P(s, gz),9}")) + $"{P(zh, gz),9}   {(double)symB8 / d.Length,20:F2} {(double)symP16 / d.Length:F2}");
        }
        Console.WriteLine($"{"TOTAL",-26}{raw,11}" + string.Join("", tot.Select(s => $"{P(s, gzT),9}")) + $"{P(zhT, gzT),9}");
        return 0;
    }

    // ---------------------------------------------------------------- transforms
    static int[] SuffixArray(int[] s, int K)
    {
        // s ends with the unique sentinel 0 ; reuse the SA-IS of Bz2Al through a tiny adapter
        var sa = new int[s.Length];
        new Bz2Al().SuffixArray(s, sa, K);
        return sa;
    }

    /// <summary>Sentinel BWT of symbols v[0..m-1] (values 0..K-1) : L without the sentinel row.</summary>
    static int[] Bwt(int[] v, int K)
    {
        int m = v.Length;
        var s = new int[m + 1];
        for (int i = 0; i < m; i++) s[i] = v[i] + 1;
        var sa = SuffixArray(s, K + 1);
        var L = new int[m];
        int o = 0;
        for (int r = 0; r <= m; r++)
        {
            int p = sa[r];
            if (p == 0) continue; // the row of the whole string : its L is the sentinel (primary index)
            L[o++] = v[p - 1];
        }
        return L;
    }

    /// <summary>
    /// BWT column coded with a bounded move-to-front of the K last distinct bytes : same as the previous byte -> run
    /// (RUNA / RUNB), rank 1..K-1 in the list -> symbol 2 + rank - 1, else literal byte -> symbol K + 1 + byte ; K = 1 : B8,
    /// K = 256 : full MTF (bzip2 ranks, literals never used).
    /// </summary>
    static (long bytes, long syms) SizeRecent(int[] L, int K)
    {
        var syms = new List<int>(L.Length);
        var rec = new List<int>();
        int run = 0;
        foreach (var c in L)
        {
            if (rec.Count > 0 && rec[0] == c) { run++; continue; }
            if (run > 0) PutRun(syms, run);
            run = 0;
            int j = rec.IndexOf(c);
            if (j > 0) { syms.Add(2 + j - 1); rec.RemoveAt(j); }
            else { syms.Add(K + 1 + c); if (rec.Count == K) rec.RemoveAt(K - 1); }
            rec.Insert(0, c);
        }
        if (run > 0) PutRun(syms, run);
        int alpha = K + 1 + 256 + 1;
        syms.Add(alpha - 1);
        // alphabet compaction : the unused symbols are dropped (bzip2 keeps only the used bytes)
        var used = syms.Distinct().OrderBy(x => x).ToArray();
        var map = new Dictionary<int, int>();
        for (int i = 0; i < used.Length; i++) map[used[i]] = i;
        var comp = syms.Select(x => map[x]).ToList();
        return ((MultiTable(comp, used.Length) + 7) / 8 + 3 + 32 + (K > 1 ? 32 : 0), syms.Count);
    }

    static (long bytes, long syms) SizeB8(byte[] blk)
    {
        var v = new int[blk.Length];
        for (int i = 0; i < v.Length; i++) v[i] = blk[i];
        var L = Bwt(v, 256);
        var syms = new List<int>(L.Length);
        int prev = -1, run = 0;
        foreach (var c in L)
        {
            if (c == prev) { run++; continue; }
            if (run > 0) PutRun(syms, run);
            run = 0; prev = c; syms.Add(c + 2);
        }
        if (run > 0) PutRun(syms, run);
        syms.Add(258); // EOB
        return ((MultiTable(syms, 259) + 7) / 8 + 3 + 32, syms.Count); // + primary index, + 256-bit used map
    }

    static (long bytes, long syms) SizeP16(byte[] blk, int align)
    {
        int m = (blk.Length - align) / 2;
        var v = new int[m];
        for (int i = 0; i < m; i++) v[i] = blk[align + 2 * i] * 256 + blk[align + 2 * i + 1];
        int loose = blk.Length - 2 * m; // 0-2 bytes stored raw
        var L = Bwt(v, 65536);
        var hi = new List<int>(m);
        var lo = new List<int>(m);
        int prev = -1, run = 0;
        foreach (var c in L)
        {
            if (c == prev) { run++; continue; }
            if (run > 0) PutRun(hi, run);
            run = 0; prev = c; hi.Add((c >> 8) + 2); lo.Add(c & 255);
        }
        if (run > 0) PutRun(hi, run);
        hi.Add(258);
        long bits = MultiTable(hi, 259) + MultiTable(lo, 256);
        return ((bits + 7) / 8 + 3 + 64 + loose, hi.Count + lo.Count);
    }

    static void PutRun(List<int> syms, int run)
    {
        // bijective base-2 run length with digits RUNA (1) / RUNB (2), as bzip2
        int z = run - 1;
        while (true)
        {
            syms.Add((z & 1) != 0 ? 1 : 0);
            if (z < 2) break;
            z = (z - 2) / 2;
        }
    }

    // ---------------------------------------------------------------- bzip2-style multi-table Huffman size (bits)
    static long MultiTable(List<int> mtfv, int alphaSize)
    {
        int nMTF = mtfv.Count;
        if (nMTF == 0) return 0;
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
        int nSel = (nMTF + 49) / 50;
        var selector = new int[nSel];
        var cost = new long[nGroups];
        for (int iter = 0; iter < 4; iter++)
        {
            var rfreq = new int[nGroups, alphaSize];
            int gs = 0, ns = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1);
                Array.Clear(cost);
                for (int x = gs; x <= ge; x++) for (int t = 0; t < nGroups; t++) cost[t] += len[t, mtfv[x]];
                int bt = 0;
                for (int t = 1; t < nGroups; t++) if (cost[t] < cost[bt]) bt = t;
                selector[ns++] = bt;
                for (int x = gs; x <= ge; x++) rfreq[bt, mtfv[x]]++;
                gs = ge + 1;
            }
            for (int t = 0; t < nGroups; t++) Lengths(len, rfreq, t, alphaSize, 17);
        }
        long bits = 3 + 15 + 16; // nGroups, nSelectors, alphabet map (approx : 16 + used 16-bit groups, small)
        var pos = Enumerable.Range(0, nGroups).ToArray();
        foreach (var s in selector)
        {
            int j = Array.IndexOf(pos, s);
            for (int k = j; k > 0; k--) pos[k] = pos[k - 1];
            pos[0] = s;
            bits += j + 1;
        }
        for (int t = 0; t < nGroups; t++)
        {
            int curr = len[t, 0];
            bits += 5;
            for (int v = 0; v < alphaSize; v++) { bits += 2 * Math.Abs(len[t, v] - curr) + 1; curr = len[t, v]; }
        }
        {
            int gs = 0, sc = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1), t = selector[sc++];
                for (int x = gs; x <= ge; x++) bits += len[t, mtfv[x]];
                gs = ge + 1;
            }
        }
        return bits;
    }

    static void Lengths(int[,] len, int[,] freq, int t, int alphaSize, int maxLen)
    {
        var w = new long[alphaSize];
        for (int i = 0; i < alphaSize; i++) w[i] = Math.Max(1, freq[t, i]);
        while (true)
        {
            var pq = new PriorityQueue<int, (long, int)>();
            int nodes = alphaSize;
            var parent = new int[2 * alphaSize];
            var depth = new int[2 * alphaSize];
            for (int i = 0; i < alphaSize; i++) { pq.Enqueue(i, (w[i], 0)); parent[i] = -1; }
            var wt = new long[2 * alphaSize];
            Array.Copy(w, wt, alphaSize);
            while (pq.Count > 1)
            {
                pq.TryDequeue(out int a, out var pa); pq.TryDequeue(out int b, out var pb);
                parent[a] = parent[b] = nodes; parent[nodes] = -1;
                wt[nodes] = pa.Item1 + pb.Item1; depth[nodes] = 1 + Math.Max(pa.Item2, pb.Item2);
                pq.Enqueue(nodes, (wt[nodes], depth[nodes])); nodes++;
            }
            int mx = 0;
            for (int i = 0; i < alphaSize; i++) { int d = 0, k = i; while (parent[k] >= 0) { k = parent[k]; d++; } len[t, i] = Math.Max(1, d); mx = Math.Max(mx, d); }
            if (mx <= maxLen) return;
            for (int i = 0; i < alphaSize; i++) w[i] = 1 + w[i] / 2;
        }
    }

    static string P(long a, long gz) => $"{100.0 * (a - gz) / gz:+0.0;-0.0}%";

    static long Gz(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }
}
