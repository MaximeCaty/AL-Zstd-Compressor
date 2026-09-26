namespace ZstdAlPort;

/*
    Brotli-style literal context modeling on the literals of the AL zstd parse (estimate) : each literal gets a context
    from the 2 previous bytes of the data (brotli : 64 contexts, one mode per block type), contexts are clustered into
    Huffman trees (greedy merge while it saves bits, tree cost ~ 4.5 bits per used symbol + 16), the context map costs ~2
    bits per context. Ratio = best mode bits / one-tree bits, applied to the real zstd literal section size, so the crude
    tree-cost model cancels out. Modes : LSB6 (p1 & 63), MSB6 (p1 >> 2), TEXT (class p1 x class p2, 8 x 8), SIGNED
    (signed magnitude buckets of p1 x p2, 8 x 8) ; brotli's UTF8 / SIGNED tables are close to the last two.
*/
public static class BrotliLit
{
    static readonly int[] Cls = MakeCls();
    static int[] MakeCls()
    {
        var c = new int[256];
        for (int b = 0; b < 256; b++)
            c[b] = b == 0 ? 0 : b == ' ' ? 1 : b >= '0' && b <= '9' ? 2 : b >= 'A' && b <= 'Z' ? 3 : b >= 'a' && b <= 'z' ? 4
                : b < 32 ? 5 : b >= 128 ? 6 : 7;
        return c;
    }
    static int Sgn(int b) { int v = (sbyte)(byte)b; int a = Math.Abs(v); return (v < 0 ? 4 : 0) + (a < 2 ? 0 : a < 16 ? 1 : a < 64 ? 2 : 3); }

    public static double Ratio(byte[] T, int start, int nbSeq, int[] seqLL, int[] seqML, int litCount)
    {
        if (litCount < 64) return 1;
        var lits = new byte[litCount]; var p1 = new byte[litCount]; var p2 = new byte[litCount];
        int pos = start, k = 0; // 0-based data position ; T is 1-based
        void Take(int n) { for (int i = 0; i < n; i++, pos++) { lits[k] = T[pos + 1]; p1[k] = pos >= 1 ? T[pos] : (byte)0; p2[k] = pos >= 2 ? T[pos - 1] : (byte)0; k++; } }
        for (int q = 1; q <= nbSeq; q++) { Take(seqLL[q]); pos += seqML[q]; }
        Take(litCount - k);
        double one = Cost(Hist(lits, new int[litCount], 1)[0]);
        double best = one;
        for (int mode = 0; mode < 4; mode++)
        {
            var ctx = new int[litCount];
            for (int i = 0; i < litCount; i++)
                ctx[i] = mode switch
                {
                    0 => p1[i] & 63,
                    1 => p1[i] >> 2,
                    2 => Cls[p1[i]] * 8 + Cls[p2[i]],
                    _ => Sgn(p1[i]) * 8 + Sgn(p2[i]),
                };
            best = Math.Min(best, Clustered(Hist(lits, ctx, 64)) + 2 * 64);
        }
        return best / one;
    }

    static int[][] Hist(byte[] lits, int[] ctx, int nCtx)
    {
        var h = new int[nCtx][];
        for (int c = 0; c < nCtx; c++) h[c] = new int[256];
        for (int i = 0; i < lits.Length; i++) h[ctx[i]][lits[i]]++;
        return h;
    }

    static double Cost(int[] h)
    {
        long n = 0; int used = 0;
        foreach (var x in h) if (x > 0) { n += x; used++; }
        if (n == 0) return 0;
        double bits = 16 + 4.5 * used;
        foreach (var x in h) if (x > 0) bits -= x * Math.Log2((double)x / n);
        return bits;
    }

    static double Clustered(int[][] h)
    {
        var cl = h.Where(x => x.Any(v => v > 0)).Select(x => (int[])x.Clone()).ToList();
        var cost = cl.Select(Cost).ToList();
        while (cl.Count > 1)
        {
            double bestD = 0; int ba = -1, bb = -1;
            for (int a = 0; a < cl.Count; a++)
                for (int b = a + 1; b < cl.Count; b++)
                {
                    var m = new int[256];
                    for (int s = 0; s < 256; s++) m[s] = cl[a][s] + cl[b][s];
                    double d = Cost(m) - cost[a] - cost[b];
                    if (d < bestD) { bestD = d; ba = a; bb = b; }
                }
            if (ba < 0) break;
            for (int s = 0; s < 256; s++) cl[ba][s] += cl[bb][s];
            cost[ba] = Cost(cl[ba]);
            cl.RemoveAt(bb); cost.RemoveAt(bb);
        }
        return cost.Sum();
    }
}
