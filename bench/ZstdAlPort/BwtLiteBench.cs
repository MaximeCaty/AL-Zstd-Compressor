using System.IO.Compression;

namespace ZstdAlPort;

/*
    `--bwtl <file or dir>... [--k K] [--iters N] [--maxlen M] [--stmt-ns X]` : AL-style BWT-lite codec (BwtLiteAl), round
    trip checked, sizes vs GZip and the AL zstd encoder, AL time per stage (statements x StmtNs + appends x 70 ns).
*/
public static class BwtLiteBench
{
    public static int Run(string[] args)
    {
        double stmtNs = 20, appendNs = 70;
        var codec = new BwtLiteAl();
        var paths = new List<string>();
        bool quiet = false;
        for (int i = 0; i < args.Length; i++)
            switch (args[i])
            {
                case "--k": codec.K = int.Parse(args[++i]); break;
                case "--iters": codec.NIters = int.Parse(args[++i]); break;
                case "--maxlen": codec.MaxCodeLen = int.Parse(args[++i]); break;
                case "--stmt-ns": stmtNs = double.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); break;
                case "--quiet": quiet = true; break;
                default: paths.Add(args[i]); break;
            }
        var files = paths.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
        var zenc = new ZstdAlEncoder();
        var zh = new Stats();
        long raw = 0, gzT = 0, bwT = 0, zhT = 0;
        if (!quiet) Console.WriteLine($"{"file",-26}{"raw",11}{"bwt-lite",10}{"zstd-H",9}   (size vs gz-opt)   AL enc / dec s/MB");
        foreach (var f in files)
        {
            var d = File.ReadAllBytes(f);
            var before = (long[])codec.St.Clone(); long ea = codec.EncAppends, da = codec.DecAppends;
            var z = codec.Compress(d);
            if (!codec.Decompress(z).AsSpan().SequenceEqual(d)) throw new Exception("round trip failed " + f);
            long gz = Gz(d), h = zenc.Compress(d, ZstdLevel.Heavy).Length;
            zh.Add(zenc.Stats);
            raw += d.Length; gzT += gz; bwT += z.Length; zhT += h;
            double enc = (codec.EncAppends - ea) * appendNs, dec = (codec.DecAppends - da) * appendNs;
            for (int s = 0; s < 10; s++) (s < BwtLiteAl.DTbl ? ref enc : ref dec) += (codec.St[s] - before[s]) * stmtNs;
            double mb = d.Length / 1048576.0;
            if (!quiet) Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,11}{P(z.Length, gz),10}{P(h, gz),9}   {enc / 1e9 / mb,16:F2} / {dec / 1e9 / mb:F2}");
        }
        double tmb = raw / 1048576.0;
        Console.WriteLine($"{"TOTAL (K=" + codec.K + ", iters=" + codec.NIters + ", maxlen=" + codec.MaxCodeLen + ")",-37}{P(bwT, gzT),10}{P(zhT, gzT),9}");
        double encMs = codec.EncAppends * appendNs / 1e6 / tmb, decMs = codec.DecAppends * appendNs / 1e6 / tmb;
        for (int s = 0; s < 10; s++)
        {
            double ms = codec.St[s] * stmtNs / 1e6 / tmb;
            if (s < BwtLiteAl.DTbl) encMs += ms; else decMs += ms;
            if (!quiet) Console.WriteLine($"  {(s < BwtLiteAl.DTbl ? "enc" : "dec")} {BwtLiteAl.StageNames[s],-16}{(double)codec.St[s] / raw,8:F2} stmt/B {ms,7:F0} ms/MB");
        }
        if (!quiet)
        {
            Console.WriteLine($"  enc appends {(double)codec.EncAppends / raw,20:F2} /B {codec.EncAppends * appendNs / 1e6 / tmb,7:F0} ms/MB");
            Console.WriteLine($"  dec appends {(double)codec.DecAppends / raw,20:F2} /B {codec.DecAppends * appendNs / 1e6 / tmb,7:F0} ms/MB");
        }
        Console.WriteLine($"BWT-lite AL : encode ~{encMs:F0} ms/MB, decode ~{decMs:F0} ms/MB | zstd AL Heavy encode ~{zh.EstimatedAlMs() / tmb:F0} ms/MB, decode ~40 ms/MB");
        return 0;
    }

    static string P(long a, long gz) => $"{100.0 * (a - gz) / gz:+0.0;-0.0}%";

    static long Gz(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }
}
