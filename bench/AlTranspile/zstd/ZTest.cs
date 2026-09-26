using System.Diagnostics;
using AlGen;

/*
    Runs the AL codeunit "TOO ZSTD Data Compression" (transpiled by al2cs.py, see run.sh) :
    default : compress files at the levels, streams checked with zstd -d and the AL Decompress ; real zstd streams (-1 -3 -9
              -19) decoded by the AL Decompress. [--levels Fast,Medium,Heavy] [--profile ColumnData]
    --hashes files : size + SHA-256 of every stream (Fast / Medium / Heavy x General / ColumnData) : output identity check
    --profile-corpus Level Profile files : AL time model, 20 ns / statement + 450 ns / call (COUNT=1 run.sh)
    --profile-run file [Level] [Profile] : statements / calls per procedure (PROFILE_DUMP=prefix : statements per AL line)
*/
var files = new List<string>();
string mode = args.Length > 0 && args[0].StartsWith("--") ? args[0] : "";
int argi = mode == "" ? 0 : 1;
TOO_ZSTD_Level lvC = TOO_ZSTD_Level.Medium; TOO_ZSTD_Profile prC = TOO_ZSTD_Profile.General;
if (mode == "--profile-corpus") { lvC = Enum.Parse<TOO_ZSTD_Level>(args[1]); prC = Enum.Parse<TOO_ZSTD_Profile>(args[2]); argi = 3; }
if (mode == "--profile-run")
{
    // --profile-run <file> [Level] [Profile], as the Brotli harness
    if (args.Length > 2) lvC = Enum.Parse<TOO_ZSTD_Level>(args[2]);
    prC = args.Length > 3 ? Enum.Parse<TOO_ZSTD_Profile>(args[3]) : TOO_ZSTD_Profile.ColumnData;
    files.Add(args[1]);
    argi = args.Length;
}
var levels = new List<TOO_ZSTD_Level> { TOO_ZSTD_Level.Fast, TOO_ZSTD_Level.Medium, TOO_ZSTD_Level.Heavy };
var profile = TOO_ZSTD_Profile.General;
for (int i = argi; i < args.Length; i++)
    if (args[i] == "--levels") levels = args[++i].Split(',').Select(Enum.Parse<TOO_ZSTD_Level>).ToList();
    else if (args[i] == "--profile") profile = Enum.Parse<TOO_ZSTD_Profile>(args[++i]);
    else files.AddRange(Directory.Exists(args[i]) ? Directory.GetFiles(args[i]).OrderBy(f => f) : new[] { args[i] });
var cu = new TOO_ZSTD_Data_Compression();
if (mode == "--hashes")
{
    foreach (var f in files)
        foreach (var pr in new[] { TOO_ZSTD_Profile.General, TOO_ZSTD_Profile.ColumnData })
            foreach (var lv in new[] { TOO_ZSTD_Level.Fast, TOO_ZSTD_Level.Medium, TOO_ZSTD_Level.Heavy })
            {
                var z = Enc(cu, File.ReadAllBytes(f), lv, pr);
                Console.WriteLine($"{Path.GetFileName(f)} {pr} {lv} {z.Length} {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(z))[..16]}");
            }
    return;
}
if (mode == "--profile-run")
{
    // per procedure : statements / calls of one file (last of the list), compress then decompress
    var d = File.ReadAllBytes(files[^1]);
    Enc(cu, new byte[] { 1, 2, 3 }, lvC, prC);
    Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); Array.Clear(ALRt.LS);
    var z = Enc(cu, d, lvC, prC);
    var encS = (long[])ALRt.S.Clone(); var encC = (long[])ALRt.Calls.Clone(); var encL = (long[])ALRt.LS.Clone();
    Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); Array.Clear(ALRt.LS);
    if (!Dec(cu, z).AsSpan().SequenceEqual(d)) throw new Exception("roundtrip");
    var src = File.ReadAllLines("../../../zstd/TOOZSTDDataCompression.Codeunit.al");
    var procOf = new string[src.Length + 1]; string curP = "";
    for (int i = 0; i < src.Length; i++)
    {
        var m = System.Text.RegularExpressions.Regex.Match(src[i], @"^\s*(local\s+)?procedure\s+(\w+)");
        if (m.Success) curP = m.Groups[2].Value;
        procOf[i + 1] = curP;
    }
    foreach (var (title, st, ca, ls) in new[] { ("Compress", encS, encC, encL), ("Decompress", ALRt.S, ALRt.Calls, ALRt.LS) })
    {
        var dump = Environment.GetEnvironmentVariable("PROFILE_DUMP");
        if (dump != null)
            File.WriteAllLines(dump + "." + title, Enumerable.Range(1, src.Length).Where(i => ls[i] > 0)
                .Select(i => $"{ls[i],12} {procOf[i],-18} {i,5}: {src[i - 1].Trim()}"));
        double sum = 0;
        var rows = new List<(string, long, long, double)>();
        for (int i = 0; i < TOO_ZSTD_Data_Compression.ProcNames.Length; i++)
            if (st[i] + ca[i] > 0) { double ms = (st[i] * 20.0 + ca[i] * 450.0) / 1e6; sum += ms; rows.Add((TOO_ZSTD_Data_Compression.ProcNames[i], st[i], ca[i], ms)); }
        Console.WriteLine($"-- {title} : ~{sum:F0} ms ({sum / (d.Length / 1048576.0):F0} ms/MB), {Path.GetFileName(files[^1])} {d.Length} B -> {z.Length} B, {lvC} {prC}");
        foreach (var r in rows.OrderByDescending(r => r.Item4).Take(12))
            Console.WriteLine($"   {r.Item1,-22}{r.Item2,14:N0} stmt {r.Item3,11:N0} calls {r.Item4,8:F0} ms");
    }
    return;
}
if (mode == "--profile-corpus")
{
    Enc(cu, new byte[] { 1, 2, 3 }, lvC, prC);
    double encMs = 0, decMs = 0; long rawC = 0, zC = 0;
    foreach (var f in files)
    {
        var d = File.ReadAllBytes(f);
        Array.Clear(ALRt.S); Array.Clear(ALRt.Calls);
        var z = Enc(cu, d, lvC, prC);
        double e = (ALRt.S.Sum() * 20.0 + ALRt.Calls.Sum() * 450.0) / 1e6;
        Array.Clear(ALRt.S); Array.Clear(ALRt.Calls);
        if (!Dec(cu, z).AsSpan().SequenceEqual(d)) throw new Exception("roundtrip " + f);
        double dm = (ALRt.S.Sum() * 20.0 + ALRt.Calls.Sum() * 450.0) / 1e6;
        encMs += e; decMs += dm; rawC += d.Length; zC += z.Length;
        Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,10} {100.0 * z.Length / d.Length,6:F2} %  enc {e / (d.Length / 1048576.0),6:F0} ms/MB  dec {dm / (d.Length / 1048576.0),5:F0} ms/MB");
    }
    double mb = rawC / 1048576.0;
    Console.WriteLine($"TOTAL {rawC} B {100.0 * zC / rawC:F2} % : compress {encMs:F0} ms ({encMs / mb:F0} ms/MB), decompress {decMs:F0} ms ({decMs / mb:F0} ms/MB), {lvC} {prC}");
    return;
}
var sw = Stopwatch.StartNew();
int nReal = 0;
var tmp = Path.Combine(Path.GetTempPath(), "zt-" + Environment.ProcessId);
Directory.CreateDirectory(tmp);
foreach (var f in files)
{
    var d = File.ReadAllBytes(f);
    var line = $"{Path.GetFileName(f),-26}{d.Length,10}";
    foreach (var lv in levels)
    {
        var z = Enc(cu, d, lv, profile);
        File.WriteAllBytes(Path.Combine(tmp, "a.zst"), z);
        var p = Process.Start(new ProcessStartInfo("zstd", $"-d -q -f {tmp}/a.zst -o {tmp}/a.out") { RedirectStandardError = true });
        p.WaitForExit();
        if (p.ExitCode != 0 || !File.ReadAllBytes(Path.Combine(tmp, "a.out")).AsSpan().SequenceEqual(d)) throw new Exception($"zstd -d mismatch {f} {lv}");
        if (!Dec(cu, z).AsSpan().SequenceEqual(d)) throw new Exception($"AL Decompress mismatch {f} {lv}");
        line += $"{100.0 * z.Length / Math.Max(1, d.Length),9:F2}%";
    }
    foreach (var q in new[] { 1, 3, 9, 19 })
    {
        if (q == 19 && d.Length > 4_000_000) continue;
        File.WriteAllBytes(Path.Combine(tmp, "b"), d);
        var p = Process.Start(new ProcessStartInfo("zstd", $"-{q} -q -f {tmp}/b -o {tmp}/b.zst") { RedirectStandardError = true });
        p.WaitForExit();
        if (!Dec(cu, File.ReadAllBytes(Path.Combine(tmp, "b.zst"))).AsSpan().SequenceEqual(d)) throw new Exception($"AL Decompress mismatch on zstd -{q} {f}");
        nReal++;
    }
    Console.WriteLine(line);
}
Console.WriteLine($"OK : {files.Count} files x {levels.Count} levels (zstd -d + AL Decompress), {nReal} real zstd streams decoded by AL, {sw.Elapsed.TotalSeconds:F0} s");

static byte[] Enc(TOO_ZSTD_Data_Compression cu, byte[] d, TOO_ZSTD_Level lv, TOO_ZSTD_Profile pr)
{
    var o = new ALOutStream();
    cu.Compress(ALInStream.Of(d), o, lv, pr);
    return o.Buf.ToArray();
}
static byte[] Dec(TOO_ZSTD_Data_Compression cu, byte[] z)
{
    var o = new ALOutStream();
    cu.Decompress(ALInStream.Of(z), o);
    return o.Buf.ToArray();
}
