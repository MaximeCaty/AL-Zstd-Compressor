using System.Diagnostics;
using System.IO.Compression;
using ZstdAlPort;

/*
    Benchmark of the AL zstd encoder port against GZip (.NET GZipStream = BC codeunit "Data Compression".GZipCompress)
    and, when the zstd CLI is on the PATH, reference zstd levels. Every AL frame is checked with `zstd -d`.

    dotnet run -c Release -- <file or directory>... [--levels Fast,Medium,Heavy] [--no-verify] [--no-ref]
*/
if (args.Length > 1 && args[0] == "--tune")
{
    var sets = new List<(string, string)>();
    for (int i = 2; i < args.Length; i++)
        if (args[i] == "--set") { var kv = args[++i].Split('=', 2); sets.Add((kv[0], kv[1])); }
    return Tune.Run(args[1], sets);
}
if (args.Length > 1 && args[0] == "--brotli")
    return BrotliBench.Run(args.Skip(1).ToArray());
if (args.Length > 1 && args[0] == "--bwtl")
    return BwtLiteBench.Run(args.Skip(1).ToArray());
if (args.Length > 1 && args[0] == "--bwtlite")
    return BwtLite.Run(args.Skip(1).ToArray());
if (args.Length > 1 && args[0] == "--bzip2")
    return Bz2Bench.Run(args.Skip(1).ToArray());
var paths = new List<string>();
var levels = new List<ZstdLevel> { ZstdLevel.Fast, ZstdLevel.Medium, ZstdLevel.Heavy };
var profiles = new List<ZstdProfile> { ZstdProfile.General };
bool verify = true, reference = true;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--levels": levels = args[++i].Split(',').Select(Enum.Parse<ZstdLevel>).ToList(); break;
        case "--profiles": profiles = args[++i].Split(',').Select(Enum.Parse<ZstdProfile>).ToList(); break;
        case "--no-verify": verify = false; break;
        case "--no-ref": reference = false; break;
        default: paths.Add(args[i]); break;
    }
}
var files = paths.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
if (files.Count == 0) { Console.WriteLine("usage: <file or directory>... [--levels Fast,Medium,Heavy] [--profiles General,ColumnData] [--no-verify] [--no-ref]"); return 1; }
var runs = profiles.SelectMany(p => levels.Select(l => (Level: l, Profile: p, Name: "al-" + l + (p == ZstdProfile.ColumnData ? "/C" : "")))).ToList();
bool haveZstd = (verify || reference) && ZstdCli.Available();
if (!haveZstd) { verify = false; reference = false; }

var cols = new List<string> { "gz-fast", "gz-opt" };
cols.AddRange(runs.Select(r => r.Name));
int[] refLevels = { 1, 3, 9, 19 };
if (reference) cols.AddRange(refLevels.Select(l => "zstd-" + l));

var totals = new Dictionary<string, long>();
var alStats = runs.ToDictionary(r => r.Name, _ => new Stats());
long totalRaw = 0;
var enc = new ZstdAlEncoder(); // one instance for all files, like the SingleInstance codeunit

Console.WriteLine($"{"file",-26}{"raw",11}  " + string.Join("", cols.Select(c => $"{c,12}")) + "   (compressed size as % of raw ; al-* vs gz-opt)");
foreach (var f in files)
{
    var data = File.ReadAllBytes(f);
    totalRaw += data.Length;
    var sizes = new Dictionary<string, long>
    {
        ["gz-fast"] = GzSize(data, CompressionLevel.Fastest),
        ["gz-opt"] = GzSize(data, CompressionLevel.Optimal),
    };
    foreach (var r in runs)
    {
        var z = enc.Compress(data, r.Level, r.Profile);
        alStats[r.Name].Add(enc.Stats);
        if (verify && !ZstdCli.Decompress(z).AsSpan().SequenceEqual(data))
            throw new Exception($"round trip failed : {f} {r.Name}");
        sizes[r.Name] = z.Length;
    }
    if (reference)
        foreach (var l in refLevels) sizes["zstd-" + l] = ZstdCli.CompressedSize(f, l);
    foreach (var kv in sizes) totals[kv.Key] = totals.GetValueOrDefault(kv.Key) + kv.Value;
    Console.WriteLine($"{Path.GetFileName(f),-26}{data.Length,11}  " + string.Join("", cols.Select(c => $"{100.0 * sizes[c] / Math.Max(1, data.Length),11:F2}%"))
        + "   " + string.Join(" ", runs.Select(r => $"{Delta(sizes[r.Name], sizes["gz-opt"]),6}")));
}
Console.WriteLine(new string('-', 39 + 12 * cols.Count));
Console.WriteLine($"{"TOTAL",-26}{totalRaw,11}  " + string.Join("", cols.Select(c => $"{100.0 * totals[c] / totalRaw,11:F2}%"))
    + "   " + string.Join(" ", runs.Select(r => $"{Delta(totals[r.Name], totals["gz-opt"]),6}")));
Console.WriteLine();
Console.WriteLine("AL time model (README, ms per raw MB) :");
foreach (var l in runs.Select(r => r.Name))
{
    var s = alStats[l];
    double mb = s.RawBytes / 1048576.0;
    Console.WriteLine($"  {l,-12} ~{s.EstimatedAlMs() / mb,6:F0} ms/MB   inserts {s.Inserts / mb / 1000,7:F0}k  positions {s.Positions / mb / 1000,7:F0}k  candidates {s.Candidates / mb / 1000,7:F0}k  bytes {s.Bytes / mb / 1000,7:F0}k  (per MB)");
}
return 0;

static string Delta(long a, long b) => $"{100.0 * (a - b) / b:+0.0;-0.0}%";

static long GzSize(byte[] data, CompressionLevel level)
{
    using var ms = new MemoryStream();
    using (var gz = new GZipStream(ms, level, true)) gz.Write(data);
    return ms.Length;
}

static class ZstdCli
{
    public static bool Available()
    {
        try { return Run("-V", null, out _) == 0; } catch { return false; }
    }

    public static byte[] Decompress(byte[] frame)
    {
        if (Run("-d -c -q", frame, out var output) != 0) throw new Exception("zstd -d failed");
        return output;
    }

    public static long CompressedSize(string file, int level)
    {
        if (Run($"-{level} -c -q --no-check \"{file}\"", null, out var output) != 0) throw new Exception("zstd failed");
        return output.Length;
    }

    static int Run(string args, byte[] stdin, out byte[] stdout)
    {
        var psi = new ProcessStartInfo("zstd", args) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var outTask = Task.Run(() => { using var ms = new MemoryStream(); p.StandardOutput.BaseStream.CopyTo(ms); return ms.ToArray(); });
        var errTask = p.StandardError.ReadToEndAsync();
        if (stdin != null) p.StandardInput.BaseStream.Write(stdin);
        p.StandardInput.Close();
        stdout = outTask.Result;
        p.WaitForExit();
        var err = errTask.Result;
        if (p.ExitCode != 0) Console.Error.WriteLine(err);
        return p.ExitCode;
    }
}
