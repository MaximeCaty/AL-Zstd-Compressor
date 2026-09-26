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
