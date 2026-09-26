using System.IO.Compression;

namespace ZstdAlPort;

/*
    `--brotli <file or dir>...` : what brotli-style literal context modeling would save on the AL zstd parse (Medium and
    Heavy, General profile), plus the literal / command counts per byte that drive the AL decoder cost model.
*/
public static class BrotliBench
{
    public static int Run(string[] args)
    {
        var files = args.SelectMany(p => Directory.Exists(p) ? Directory.GetFiles(p).OrderBy(f => f).ToArray() : new[] { p }).ToList();
        foreach (var lvl in new[] { ZstdLevel.Medium, ZstdLevel.Heavy })
        {
            var enc = new ZstdAlEncoder { BrotliEstimate = true };
            var all = new Stats();
            long raw = 0, gzT = 0, zT = 0; double bT = 0;
            long smallRaw = 0, smallGz = 0, smallZ = 0; double smallB = 0;
            foreach (var f in files)
            {
                var d = File.ReadAllBytes(f);
                long z = enc.Compress(d, lvl).Length;
                var st = enc.Stats;
                all.Add(st);
                double b = z - st.LitBytes + st.BrLitBytes;
                long gz = Gz(d);
                raw += d.Length; gzT += gz; zT += z; bT += b;
                if (d.Length <= 262144) { smallRaw += d.Length; smallGz += gz; smallZ += z; smallB += b; }
                if (lvl == ZstdLevel.Heavy)
                    Console.WriteLine($"  {Path.GetFileName(f),-26}{d.Length,10}  zstd {P(z, gz),7}  +ctx literals {P(b, gz),7}   lits {(double)st.Lits / d.Length:F2}/B  cmds {(double)st.Seqs / d.Length:F3}/B");
            }
            Console.WriteLine($"{lvl,-7} all : zstd {P(zT, gzT)}  with brotli literal contexts {P(bT, gzT)} | <= 256 KB : zstd {P(smallZ, smallGz)}  ctx {P(smallB, smallGz)} | lits {(double)all.Lits / raw:F3}/B cmds {(double)all.Seqs / raw:F3}/B");
        }
        return 0;
    }

    static string P(double a, double gz) => $"{100.0 * (a - gz) / gz:+0.0;-0.0}%";

    static long Gz(byte[] d)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.Optimal, true)) g.Write(d);
        return ms.Length;
    }
}
