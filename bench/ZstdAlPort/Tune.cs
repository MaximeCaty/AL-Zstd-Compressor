using System.Collections.Concurrent;
using System.IO.Compression;

namespace ZstdAlPort;

/*
    Parameter sweep : `--tune <configs.txt> --set Name=dir ...`
    configs.txt : one config per line, "name level[:profile] key=value ..." (keys = Tuning fields, case-insensitive ; # comments).
    Per config and file set : total size vs total GZip, mean per-file size vs GZip (small files weigh the same as big ones),
    and the AL time model estimate (ms per raw MB). Configs run in parallel, one encoder per config.
*/
public static class Tune
{
    public static bool PerFile = Environment.GetEnvironmentVariable("PERFILE") == "1";
    public static int Run(string configFile, List<(string Name, string Dir)> sets)
    {
        var data = sets.Select(s => (s.Name, Files: Directory.GetFiles(s.Dir).OrderBy(f => f).Select(File.ReadAllBytes).ToArray())).ToList();
        var gz = data.Select(s => s.Files.Select(GzSize).ToArray()).ToList();
        var configs = File.ReadAllLines(configFile).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();

        Console.WriteLine($"{"config",-30}" + string.Join("", data.Select(s => $"{s.Name + " tot",11}{s.Name + " avg",10}{"ms/MB",7}")));
        var results = new ConcurrentDictionary<int, string>();
        int next = 0;
        Parallel.For(0, configs.Count, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            var parts = configs[i].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var lp = parts[1].Split(':');
            var level = Enum.Parse<ZstdLevel>(lp[0]);
            var profile = lp.Length > 1 ? Enum.Parse<ZstdProfile>(lp[1]) : ZstdProfile.General;
            var line = $"{parts[0],-30}";
            for (int si = 0; si < data.Count; si++)
            {
                var enc = new ZstdAlEncoder();
                var stats = new Stats();
                long tot = 0, gzTot = 0;
                double rel = 0;
                for (int fi = 0; fi < data[si].Files.Length; fi++)
                {
                    var t = Parse(parts.Skip(2));
                    if (t != null) enc.SetTuning(t);
                    long size = enc.Compress(data[si].Files[fi], level, profile).Length;
                    stats.Add(enc.Stats);
                    tot += size;
                    gzTot += gz[si][fi];
                    rel += (double)size / gz[si][fi] - 1;
                    if (PerFile) Console.WriteLine($"  {parts[0]} {si} {fi,3} {100.0 * size / gz[si][fi] - 100,7:+0.00;-0.00}%");
                }
                double mb = stats.RawBytes / 1048576.0;
                if (Environment.GetEnvironmentVariable("ENTROPY") == "1")
                    Console.WriteLine($"  {parts[0]} {data[si].Name}: blocks {stats.Blocks} lits {stats.Lits} -> {stats.LitBytes} B (ideal {stats.LitIdealBits / 8:F0}, +{100 * (stats.LitBytes * 8 / Math.Max(1, stats.LitIdealBits) - 1):F1}%) | seqs {stats.Seqs} -> {stats.SeqBytes} B, of which tables/header {stats.SeqHdrBytes} (ideal {stats.SeqIdealBits / 8:F0}, +{100 * (stats.SeqBytes * 8 / Math.Max(1, stats.SeqIdealBits) - 1):F1}%) | total {tot}");
                line += $"{100.0 * (tot - gzTot) / gzTot,10:+0.00;-0.00}%{100.0 * rel / data[si].Files.Length,9:+0.00;-0.00}%{stats.EstimatedAlMs() / mb,7:F0}";
            }
            results[i] = line;
            lock (results)
                while (results.TryGetValue(next, out var l)) { Console.WriteLine(l); next++; }
        });
        return 0;
    }

    static Tuning Parse(IEnumerable<string> kvs)
    {
        Tuning t = null;
        foreach (var kv in kvs)
        {
            t ??= new Tuning();
            var p = kv.Split('=');
            var f = typeof(Tuning).GetFields().First(x => x.Name.Equals(p[0], StringComparison.OrdinalIgnoreCase));
            f.SetValue(t, f.FieldType == typeof(bool) ? (object)(p[1] == "1" || p[1].Equals("true", StringComparison.OrdinalIgnoreCase)) : int.Parse(p[1]));
        }
        return t;
    }

    static long GzSize(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }
}
