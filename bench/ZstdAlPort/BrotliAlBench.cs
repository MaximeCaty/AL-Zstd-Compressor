using System.IO.Compression;

namespace ZstdAlPort;

/*
    `--brotli-al <file or dir>... [--level Medium|Heavy] [--meta N]` : AL-style brotli (BrotliAl) vs the AL zstd encoder
    (same parse) and real brotli (.NET BrotliEncoder q5 / q9 / q11, window 24).
    Checks : our streams decode with .NET BrotliDecoder and with BrotliAl.Decompress ; real brotli streams decode with
    BrotliAl.Decompress (full format coverage : dictionary, block switching, context maps...).
    AL time : statements x 20 ns + text operations (window ToText / Append) x 100 ns + literal pair appends x 70 ns.
    zstd AL decode uses the same unit costs : per literal 2.5 statements + 1/2 append (2-symbol Huffman, pair appends),
    per sequence 26 statements + 4 text operations (3 FSE symbols, extra bits, repeat offsets, 2 copies).
*/
public static class BrotliAlBench
{
    const double StmtNs = 20, TextNs = 100, AppendNs = 70;

    public static int Run(string[] args)
    {
        var level = ZstdLevel.Heavy;
        int meta = 1 << 20;
        bool noRef = false;
        var paths = new List<string>();
        for (int i = 0; i < args.Length; i++)
            if (args[i] == "--level") level = Enum.Parse<ZstdLevel>(args[++i]);
            else if (args[i] == "--meta") meta = int.Parse(args[++i]);
            else if (args[i] == "--no-ref") noRef = true;
            else paths.Add(args[i]);
        var files = paths.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
        var br = new BrotliAl { Level = level, MetaMax = meta };
        var brDec = new BrotliAl();
        var refDec = new BrotliAl();
        var zenc = new ZstdAlEncoder();
        long raw = 0, gzT = 0, bT = 0, zT = 0, q5T = 0, q9T = 0, q11T = 0;
        double zDecNs = 0, zEncMs = 0, refDecNs = 0; long refRaw = 0;
        Console.WriteLine($"{"file",-26}{"raw",10}{"br-AL",8}{"zstd-AL",9}{"br q5",8}{"br q9",8}{"br q11",8}  (vs gz-opt)  AL decode ms/MB br / zstd");
        foreach (var f in files)
        {
            var d = File.ReadAllBytes(f);
            var before = (long[])brDec.St.Clone(); long to0 = brDec.TextOps, ap0 = brDec.DecAppends;
            var z = br.Compress(d);
            // checks
            if (!DotNetDecode(z).AsSpan().SequenceEqual(d)) throw new Exception("BrotliDecoder mismatch " + f);
            if (!brDec.Decompress(z).AsSpan().SequenceEqual(d)) throw new Exception("own decoder mismatch " + f);
            double decNs = 0;
            for (int s = BrotliAl.DHdr; s <= BrotliAl.DCopy; s++) decNs += (brDec.St[s] - before[s]) * StmtNs;
            decNs += (brDec.TextOps - to0) * TextNs + (brDec.DecAppends - ap0) / 2.0 * AppendNs;
            long q5 = noRef ? 0 : Real(d, 5), q9 = noRef ? 0 : Real(d, 9), q11 = !noRef && d.Length <= 4_000_000 ? Real(d, 11) : 0;
            foreach (var q in noRef ? Array.Empty<int>() : new[] { 5, 9 })
            {
                var rs = RealBytes(d, q);
                var r0 = (long[])refDec.St.Clone(); long rt = refDec.TextOps, ra = refDec.DecAppends;
                if (!refDec.Decompress(rs).AsSpan().SequenceEqual(d)) throw new Exception($"own decoder fails on real brotli q{q} " + f);
                if (q == 9)
                {
                    for (int s = BrotliAl.DHdr; s <= BrotliAl.DCopy; s++) refDecNs += (refDec.St[s] - r0[s]) * StmtNs;
                    refDecNs += (refDec.TextOps - rt) * TextNs + (refDec.DecAppends - ra) / 2.0 * AppendNs;
                    refRaw += d.Length;
                }
            }
            long zs = zenc.Compress(d, level).Length;
            var st = zenc.Stats;
            double zdec = st.Lits * (2.5 * StmtNs + AppendNs / 2) + st.Seqs * (26 * StmtNs + 4 * TextNs);
            zDecNs += zdec; zEncMs += st.EstimatedAlMs();
            long gz = Gz(d);
            raw += d.Length; gzT += gz; bT += z.Length; zT += zs; q5T += q5; q9T += q9; q11T += q11 > 0 ? q11 : q9;
            double mb = d.Length / 1048576.0;
            Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,10}{P(z.Length, gz),8}{P(zs, gz),9}{P(q5, gz),8}{P(q9, gz),8}{(q11 > 0 ? P(q11, gz) : "  -"),8}  {decNs / 1e6 / mb,18:F0} / {zdec / 1e6 / mb:F0}");
        }
        double tmb = raw / 1048576.0;
        Console.WriteLine($"{"TOTAL (" + level + ")",-36}{P(bT, gzT),8}{P(zT, gzT),9}{P(q5T, gzT),8}{P(q9T, gzT),8}{P(q11T, gzT),8}   (q11 : files <= 4 MB, else q9)");
        Console.WriteLine();
        double enc = br.ParseMs / tmb, decB = 0;
        Console.WriteLine("AL-style brotli, per stage (statements / raw byte, ms / MB) :");
        for (int s = 0; s < 10; s++)
        {
            long cnt = s < BrotliAl.DHdr ? br.St[s] : brDec.St[s];
            double ms = cnt * StmtNs / 1e6 / tmb;
            if (s == BrotliAl.EParse) ms = br.ParseMs / tmb;
            else if (s < BrotliAl.DHdr) enc += ms; else decB += ms;
            Console.WriteLine($"  {(s < BrotliAl.DHdr ? "enc" : "dec")} {BrotliAl.StageNames[s],-22}{(double)cnt / raw,7:F2} {ms,7:F0}");
        }
        enc += br.EncAppends * AppendNs / 1e6 / tmb;
        double decText = brDec.TextOps * TextNs / 1e6 / tmb, decApp = brDec.DecAppends / 2.0 * AppendNs / 1e6 / tmb;
        Console.WriteLine($"  dec text ops (window copies) {(double)brDec.TextOps / raw,7:F3} {decText,7:F0}");
        Console.WriteLine($"  dec literal pair appends     {(double)brDec.DecAppends / 2 / raw,7:F3} {decApp,7:F0}");
        Console.WriteLine($"brotli AL : encode ~{enc:F0} ms/MB, decode ~{decB + decText + decApp:F0} ms/MB (real brotli q9 streams : ~{refDecNs / 1e6 / (refRaw / 1048576.0):F0})");
        Console.WriteLine($"decoder coverage on real brotli q5 / q9 streams : {refDec.DictRefs} static dictionary words, {refDec.BlockSwitches} block switches");
        Console.WriteLine($"zstd AL   : encode ~{zEncMs / tmb:F0} ms/MB, decode ~{zDecNs / 1e6 / tmb:F0} ms/MB (same unit costs)");
        return 0;
    }

    static string P(long a, long gz) => $"{100.0 * (a - gz) / gz:+0.0;-0.0}%";
    static long Real(byte[] d, int q) => RealBytes(d, q).Length;
    static byte[] RealBytes(byte[] d, int q)
    {
        var dst = new byte[BrotliEncoder.GetMaxCompressedLength(d.Length)];
        if (!BrotliEncoder.TryCompress(d, dst, out int n, q, 24)) throw new Exception("BrotliEncoder failed");
        return dst[..n];
    }
    static byte[] DotNetDecode(byte[] z)
    {
        using var ms = new MemoryStream(z);
        using var bs = new BrotliStream(ms, CompressionMode.Decompress);
        using var o = new MemoryStream();
        bs.CopyTo(o);
        return o.ToArray();
    }
    static long Gz(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }
}
