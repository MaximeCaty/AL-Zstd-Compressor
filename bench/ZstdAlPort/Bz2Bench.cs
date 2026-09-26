using System.Diagnostics;
using System.IO.Compression;

namespace ZstdAlPort;

/*
    `--bzip2 <file or dir>... [--iters N] [--stmt-ns X]` : AL-style bzip2 (Bz2Al) vs GZip and the AL zstd encoder.
    Every bzip2 stream is checked with `bzip2 -d` and with Bz2Al.Decompress ; AL time = statements x StmtNs + appends x 70 ns.
*/
public static class Bz2Bench
{
    public static int Run(string[] args)
    {
        double stmtNs = 20, appendNs = 70;
        int iters = 4;
        bool noMtf = false;
        var paths = new List<string>();
        for (int i = 0; i < args.Length; i++)
            if (args[i] == "--iters") iters = int.Parse(args[++i]);
            else if (args[i] == "--no-mtf") noMtf = true;
            else if (args[i] == "--stmt-ns") stmtNs = double.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture);
            else paths.Add(args[i]);
        var files = paths.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();

        var bz = new Bz2Al { NIters = iters, NoMtf = noMtf };
        var zenc = new ZstdAlEncoder();
        var zMed = new Stats(); var zHeavy = new Stats();
        long raw = 0, gzT = 0, bzT = 0, zmT = 0, zhT = 0;
        Console.WriteLine($"{"file",-26}{"raw",11}{"bz2-AL",9}{"zstd-M",9}{"zstd-H",9}   (size vs gz-opt)   bz2 AL enc / dec (s/MB)");
        foreach (var f in files)
        {
            var d = File.ReadAllBytes(f);
            var before = (long[])bz.St.Clone(); long ea = bz.EncAppends, da = bz.DecAppends;
            var z = bz.Compress(d);
            if (!noMtf && !Native(z).AsSpan().SequenceEqual(d)) throw new Exception("bzip2 -d mismatch " + f);
            if (!noMtf && !bz.Decompress(z).AsSpan().SequenceEqual(d)) throw new Exception("own decoder mismatch " + f);
            long gz = Gz(d);
            long zm = zenc.Compress(d, ZstdLevel.Medium).Length; zMed.Add(zenc.Stats);
            long zh = zenc.Compress(d, ZstdLevel.Heavy).Length; zHeavy.Add(zenc.Stats);
            raw += d.Length; gzT += gz; bzT += z.Length; zmT += zm; zhT += zh;
            double mb = d.Length / 1048576.0;
            double enc = 0, dec = 0;
            for (int s = 0; s < 14; s++) (s < Bz2Al.DHuf ? ref enc : ref dec) += (bz.St[s] - before[s]) * stmtNs;
            enc += (bz.EncAppends - ea) * appendNs; dec += (bz.DecAppends - da) * appendNs;
            Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,11}{P(z.Length, gz),9}{P(zm, gz),9}{P(zh, gz),9}   {enc / 1e9 / mb,20:F2} / {dec / 1e9 / mb:F2}");
        }
        double tmb = raw / 1048576.0;
        Console.WriteLine($"{"TOTAL",-26}{raw,11}{P(bzT, gzT),9}{P(zmT, gzT),9}{P(zhT, gzT),9}");
        Console.WriteLine();
        Console.WriteLine($"AL-style bzip2 statements per raw byte and estimated AL time ({stmtNs} ns / statement, {appendNs} ns / append) :");
        double encMs = 0, decMs = 0;
        for (int s = 0; s < 14; s++)
        {
            double ms = bz.St[s] * stmtNs / 1e6 / tmb;
            if (s < Bz2Al.DHuf) encMs += ms; else decMs += ms;
            Console.WriteLine($"  {(s < Bz2Al.DHuf ? "enc" : "dec")} {Bz2Al.StageNames[s],-16}{(double)bz.St[s] / raw,8:F1} stmt/B {ms,8:F0} ms/MB");
        }
        encMs += bz.EncAppends * appendNs / 1e6 / tmb; decMs += bz.DecAppends * appendNs / 1e6 / tmb;
        Console.WriteLine($"  enc appends {(double)bz.EncAppends / raw,21:F3} /B {bz.EncAppends * appendNs / 1e6 / tmb,8:F0} ms/MB");
        Console.WriteLine($"  dec appends {(double)bz.DecAppends / raw,21:F3} /B {bz.DecAppends * appendNs / 1e6 / tmb,8:F0} ms/MB");
        Console.WriteLine($"bzip2 AL : encode ~{encMs:F0} ms/MB, decode ~{decMs:F0} ms/MB (without CRC check : ~{decMs - bz.St[Bz2Al.DCrc] * stmtNs / 1e6 / tmb:F0})");
        Console.WriteLine($"zstd AL (README time model) : Medium ~{zMed.EstimatedAlMs() / tmb:F0} ms/MB, Heavy ~{zHeavy.EstimatedAlMs() / tmb:F0} ms/MB ; decode ~35-45 ms/MB (README)");
        return 0;
    }

    static string P(long a, long gz) => $"{100.0 * (a - gz) / gz:+0.0;-0.0}%";

    static long Gz(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }

    static byte[] Native(byte[] z)
    {
        var psi = new ProcessStartInfo("bzip2", "-d -c") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var o = Task.Run(() => { using var ms = new MemoryStream(); p.StandardOutput.BaseStream.CopyTo(ms); return ms.ToArray(); });
        var e = p.StandardError.ReadToEndAsync();
        p.StandardInput.BaseStream.Write(z); p.StandardInput.Close();
        var r = o.Result; p.WaitForExit();
        if (p.ExitCode != 0) throw new Exception("bzip2 -d : " + e.Result);
        return r;
    }
}
