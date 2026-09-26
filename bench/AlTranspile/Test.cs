using System.Diagnostics;
using System.IO.Compression;
using AlGen;

/*
    Runs the AL codeunit "TOO Brotli Data Compression" (transpiled by al2cs.py, see run.sh) :
    - Compress every file at the given levels, one codeunit instance for all (SingleInstance) ;
    - our streams must decode with .NET BrotliDecoder and with the AL Decompress ;
    - real brotli streams (.NET BrotliEncoder q1 / q5 / q9 / q11, window 24) must decode with the AL Decompress.
    dotnet run -- <resource folder> <file or dir>... [--levels Fast,Medium,Heavy] [--profile ColumnData]
*/
NavApp.ResourceFolder = args[0];
if (args.Length > 2 && args[1] == "--profile-run")
{
    // one roundtrip of args[2] : statements / calls per procedure (build with COUNT=1 run.sh), AL time model
    // ms = statements x StmtNs + calls x CallNs ; defaults 20 / 450 ns (README), override with args[5] / args[6]
    var d = File.ReadAllBytes(args[2]);
    var lvl = args.Length > 3 ? Enum.Parse<TOO_Brotli_Level>(args[3]) : TOO_Brotli_Level.Medium;
    var prof = args.Length > 4 ? Enum.Parse<TOO_Brotli_Profile>(args[4]) : TOO_Brotli_Profile.ColumnData;
    double sNs = args.Length > 5 ? double.Parse(args[5], System.Globalization.CultureInfo.InvariantCulture) : 20;
    double cNs = args.Length > 6 ? double.Parse(args[6], System.Globalization.CultureInfo.InvariantCulture) : 450;
    var c = new TOO_Brotli_Data_Compression();
    c.Compress(ALInStream.Of(new byte[] { 1, 2, 3 }), new ALOutStream(), lvl, prof); // one-time tables out of the count
    Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); Array.Clear(ALRt.LS);
    var o = new ALOutStream();
    c.Compress(ALInStream.Of(d), o, lvl, prof);
    var z = o.Buf.ToArray();
    var encS = (long[])ALRt.S.Clone(); var encC = (long[])ALRt.Calls.Clone(); var encL = (long[])ALRt.LS.Clone();
    Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); Array.Clear(ALRt.LS);
    var back = AlDecode(c, z);
    if (!back.AsSpan().SequenceEqual(d)) throw new Exception("roundtrip failed");
    Console.WriteLine($"{Path.GetFileName(args[2])} {d.Length} B -> {z.Length} B ({100.0 * z.Length / d.Length:F2} %), {lvl} {prof}");
    // hot AL lines (PROFILE_LINES=n) : statements per source line, with the procedure and the line text
    int nLines = int.TryParse(Environment.GetEnvironmentVariable("PROFILE_LINES"), out var nl) ? nl : 0;
    var src = nLines > 0 ? File.ReadAllLines("../../brotli/TOOBrotliDataCompression.Codeunit.al") : Array.Empty<string>();
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
        if (nLines > 0 && dump != null)
            File.WriteAllLines(dump + "." + title, Enumerable.Range(1, src.Length).Where(i => ls[i] > 0)
                .Select(i => $"{ls[i],12} {procOf[i],-18} {i,5}: {src[i - 1].Trim()}"));
        if (nLines > 0)
        {
            Console.WriteLine($"-- {title} : hot lines (statements x {sNs} ns)");
            foreach (var ln in Enumerable.Range(1, src.Length).OrderByDescending(i => ls[i]).Take(nLines))
                Console.WriteLine($"   {ls[ln] * sNs / 1e6,7:F0} ms {ls[ln],12:N0}  {procOf[ln],-18} {ln,5}: {src[ln - 1].Trim()}");
        }
        double sum = 0;
        var rows = new List<(string, long, long, double)>();
        for (int i = 0; i < TOO_Brotli_Data_Compression.ProcNames.Length; i++)
            if (st[i] + ca[i] > 0) { double ms = (st[i] * sNs + ca[i] * cNs) / 1e6; sum += ms; rows.Add((TOO_Brotli_Data_Compression.ProcNames[i], st[i], ca[i], ms)); }
        Console.WriteLine($"-- {title} : ~{sum:F0} ms ({sum / (d.Length / 1048576.0):F0} ms/MB)");
        foreach (var r in rows.OrderByDescending(r => r.Item4).Take(14))
            Console.WriteLine($"   {r.Item1,-22}{r.Item2,14:N0} stmt {r.Item3,11:N0} calls {r.Item4,8:F0} ms");
    }
    return;
}
if (args.Length > 2 && args[1] == "--hashes")
{
    // output identity check : size + SHA-256 of every stream (files x Fast/Medium/Heavy x General/ColumnData, one instance)
    var cuH = new TOO_Brotli_Data_Compression();
    var fl = args.Skip(2).SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p });
    foreach (var f in fl)
        foreach (var pr in new[] { TOO_Brotli_Profile.General, TOO_Brotli_Profile.ColumnData })
            foreach (var lv in new[] { TOO_Brotli_Level.Fast, TOO_Brotli_Level.Medium, TOO_Brotli_Level.Heavy })
            {
                var o = new ALOutStream();
                cuH.Compress(ALInStream.Of(File.ReadAllBytes(f)), o, lv, pr);
                var z = o.Buf.ToArray();
                Console.WriteLine($"{Path.GetFileName(f)} {pr} {lv} {z.Length} {Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(z))[..16]}");
            }
    return;
}
if (args.Length > 4 && args[1] == "--profile-corpus")
{
    // AL time model (20 ns / statement, 450 ns / call) of compress and decompress over files (build with COUNT=1 run.sh)
    var lvC = Enum.Parse<TOO_Brotli_Level>(args[2]);
    var prC = Enum.Parse<TOO_Brotli_Profile>(args[3]);
    var cuC = new TOO_Brotli_Data_Compression();
    cuC.Compress(ALInStream.Of(new byte[] { 1, 2, 3 }), new ALOutStream(), lvC, prC);
    double encMs = 0, decMs = 0; long rawC = 0, zC = 0;
    long encSt = 0, encCa = 0, encTr = 0, encAo = 0, decSt = 0, decCa = 0, decTr = 0, decAo = 0;
    foreach (var f in args.Skip(4).SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }))
    {
        var d = File.ReadAllBytes(f);
        Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); ALRt.TextReads = 0; ALRt.ArrayOps = 0;
        var o = new ALOutStream();
        cuC.Compress(ALInStream.Of(d), o, lvC, prC);
        double e = (ALRt.S.Sum() * 20.0 + ALRt.Calls.Sum() * 450.0) / 1e6;
        encSt += ALRt.S.Sum(); encCa += ALRt.Calls.Sum(); encTr += ALRt.TextReads; encAo += ALRt.ArrayOps;
        Array.Clear(ALRt.S); Array.Clear(ALRt.Calls); ALRt.TextReads = 0; ALRt.ArrayOps = 0;
        var z = o.Buf.ToArray();
        if (!AlDecode(cuC, z).AsSpan().SequenceEqual(d)) throw new Exception("roundtrip " + f);
        double dm = (ALRt.S.Sum() * 20.0 + ALRt.Calls.Sum() * 450.0) / 1e6;
        decSt += ALRt.S.Sum(); decCa += ALRt.Calls.Sum(); decTr += ALRt.TextReads; decAo += ALRt.ArrayOps;
        encMs += e; decMs += dm; rawC += d.Length; zC += z.Length;
        Console.WriteLine($"{Path.GetFileName(f),-26}{d.Length,10} {100.0 * z.Length / d.Length,6:F2} %  enc {e / (d.Length / 1048576.0),6:F0} ms/MB  dec {dm / (d.Length / 1048576.0),5:F0} ms/MB");
    }
    double mb = rawC / 1048576.0;
    Console.WriteLine($"TOTAL {rawC} B {100.0 * zC / rawC:F2} % : compress {encMs:F0} ms ({encMs / mb:F0} ms/MB), decompress {decMs:F0} ms ({decMs / mb:F0} ms/MB), {lvC} {prC}");
    // per raw MB : statements, calls, Text[i] reads, array accesses ; + 7.7 ns / Text read, 4.5 ns / array access
    Console.WriteLine($"  per MB  compress : {encSt / mb / 1e6:F2} M stmt, {encCa / mb / 1e3:F1} K calls, {encTr / mb / 1e6:F2} M text reads, {encAo / mb / 1e6:F2} M array ops -> {(encSt * 20.0 + encCa * 450.0 + encTr * 7.7 + encAo * 4.5) / 1e6 / mb:F0} ms/MB with reads");
    Console.WriteLine($"  per MB  decompress : {decSt / mb / 1e6:F2} M stmt, {decCa / mb / 1e3:F1} K calls, {decTr / mb / 1e6:F2} M text reads, {decAo / mb / 1e6:F2} M array ops -> {(decSt * 20.0 + decCa * 450.0 + decTr * 7.7 + decAo * 4.5) / 1e6 / mb:F0} ms/MB with reads");
    return;
}
if (args.Length > 3 && args[1] == "--real-window")
{
    // real brotli streams (.NET BrotliEncoder q1 / q5 / q9 / q11) with window args[2] (16..24) decoded by the AL Decompress :
    // small windows exercise the sliding output window and dictionary references past the window
    int win = int.Parse(args[2]);
    var cuW = new TOO_Brotli_Data_Compression();
    int nW = 0;
    foreach (var f in args.Skip(3).SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }))
    {
        var d = File.ReadAllBytes(f);
        foreach (var q in new[] { 1, 5, 9, 11 })
        {
            if (q == 11 && d.Length > 4_000_000) continue;
            var dst = new byte[BrotliEncoder.GetMaxCompressedLength(d.Length) + 1024];
            if (!BrotliEncoder.TryCompress(d, dst, out int n, q, win)) throw new Exception($"TryCompress {f} q{q}");
            if (!AlDecode(cuW, dst[..n]).AsSpan().SequenceEqual(d)) throw new Exception($"AL Decompress mismatch on real brotli q{q} w{win} {f}");
            nW++;
        }
        Console.WriteLine($"{Path.GetFileName(f)} ok");
    }
    Console.WriteLine($"OK : {nW} real brotli streams (window {win}) decoded by AL");
    return;
}
if (args.Length > 3 && args[1] == "--debug-pair")
{
    // compress B with a fresh instance and after A with the same instance : compare
    var a1 = File.ReadAllBytes(args[2]); var b1 = File.ReadAllBytes(args[3]);
    var fresh = new TOO_Brotli_Data_Compression(); var o1 = new ALOutStream();
    fresh.Compress(ALInStream.Of(b1), o1, TOO_Brotli_Level.Heavy, TOO_Brotli_Profile.General);
    var reused = new TOO_Brotli_Data_Compression(); var o0 = new ALOutStream();
    reused.Compress(ALInStream.Of(a1), o0, TOO_Brotli_Level.Heavy, TOO_Brotli_Profile.General);
    if (args.Length > 4) { var od = new ALOutStream(); reused.Decompress(ALInStream.Of(o0.Buf.ToArray()), od); Console.WriteLine("decompressed A in between"); }
    var o2 = new ALOutStream();
    reused.Compress(ALInStream.Of(b1), o2, TOO_Brotli_Level.Heavy, TOO_Brotli_Profile.General);
    var x = o1.Buf.ToArray(); var y = o2.Buf.ToArray();
    // last parsed block (B is one block) : sequences of both runs
    Console.WriteLine($"NbSeq fresh {fresh.NbSeq} reused {reused.NbSeq} ; NTrees fresh {fresh.NTrees} reused {reused.NTrees}");
    Console.WriteLine("CMap fresh  " + string.Join(",", fresh.CMap)); Console.WriteLine("CMap reused " + string.Join(",", reused.CMap));
    Console.WriteLine("ClCost fresh  " + string.Join(",", fresh.ClCost.Take(8))); Console.WriteLine("ClCost reused " + string.Join(",", reused.ClCost.Take(8)));
    for (int k = 1; k <= Math.Min(fresh.NbSeq, reused.NbSeq); k++)
        if (fresh.SeqLL[k] != reused.SeqLL[k] || fresh.SeqML[k] != reused.SeqML[k] || fresh.SeqOff[k] != reused.SeqOff[k])
        { Console.WriteLine($"first differing sequence {k} : fresh {fresh.SeqLL[k]}/{fresh.SeqML[k]}/{fresh.SeqOff[k]} reused {reused.SeqLL[k]}/{reused.SeqML[k]}/{reused.SeqOff[k]}"); break; }
    int i0 = 0; while (i0 < Math.Min(x.Length, y.Length) && x[i0] == y[i0]) i0++;
    Console.WriteLine($"fresh {x.Length} B, reused {y.Length} B, first difference at byte {i0}");
    return;
}
var levels = new List<TOO_Brotli_Level> { TOO_Brotli_Level.Medium, TOO_Brotli_Level.Heavy };
var profile = TOO_Brotli_Profile.General;
var paths = new List<string>();
for (int i = 1; i < args.Length; i++)
    if (args[i] == "--levels") levels = args[++i].Split(',').Select(Enum.Parse<TOO_Brotli_Level>).ToList();
    else if (args[i] == "--profile") profile = Enum.Parse<TOO_Brotli_Profile>(args[++i]);
    else paths.Add(args[i]);
var files = paths.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
var cu = new TOO_Brotli_Data_Compression();
long raw = 0, gzT = 0; var tot = levels.ToDictionary(l => l, _ => 0L);
int realChecked = 0;
var sw = Stopwatch.StartNew();
Console.WriteLine($"{"file",-26}{"raw",10}" + string.Join("", levels.Select(l => $"{"AL-" + l,11}")) + "   (size vs gz-opt ; all round trips checked)");
foreach (var f in files)
{
    var d = File.ReadAllBytes(f);
    long gz = Gz(d);
    raw += d.Length; gzT += gz;
    var line = $"{Path.GetFileName(f),-26}{d.Length,10}";
    foreach (var lvl in levels)
    {
        var o = new ALOutStream();
        cu.Compress(ALInStream.Of(d), o, lvl, profile);
        var z = o.Buf.ToArray();
        if (!DotNetDecode(z).AsSpan().SequenceEqual(d)) throw new Exception($"BrotliDecoder mismatch {f} {lvl}");
        if (!AlDecode(cu, z).AsSpan().SequenceEqual(d)) throw new Exception($"AL Decompress mismatch on AL stream {f} {lvl}");
        tot[lvl] += z.Length;
        line += $"{100.0 * (z.Length - gz) / gz,10:+0.0;-0.0}%";
    }
    foreach (var q in new[] { 1, 5, 9, 11 })
    {
        if (q == 11 && d.Length > 2_000_000) continue;
        var dst = new byte[BrotliEncoder.GetMaxCompressedLength(d.Length) + 1024];
        int n;
        if (!BrotliEncoder.TryCompress(d, dst, out n, q, 24))
        {
            // TryCompress can refuse near the bound : stream encoder instead
            using var ms = new MemoryStream();
            using (var enc = new BrotliStream(ms, (CompressionLevel)(q < 5 ? 1 : 0), true)) enc.Write(d);
            dst = ms.ToArray(); n = dst.Length;
        }
        if (!AlDecode(cu, dst[..n]).AsSpan().SequenceEqual(d)) throw new Exception($"AL Decompress mismatch on real brotli q{q} {f}");
        realChecked++;
    }
    Console.WriteLine(line);
}
Console.WriteLine($"{"TOTAL",-26}{raw,10}" + string.Join("", levels.Select(l => $"{100.0 * (tot[l] - gzT) / gzT,10:+0.0;-0.0}%")));
Console.WriteLine($"OK : {files.Count} files x {levels.Count} levels round trip (BrotliDecoder + AL Decompress), {realChecked} real brotli streams decoded by AL, {sw.Elapsed.TotalSeconds:F0} s");

static byte[] AlDecode(TOO_Brotli_Data_Compression cu, byte[] z)
{
    var o = new ALOutStream();
    cu.Decompress(ALInStream.Of(z), o);
    return o.Buf.ToArray();
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
