# AL zstd encoder: C# port and benchmark

`ZstdAlPort/ZstdAlEncoder.cs` ports the **Compress** side of `TOOZSTDDataCompression.Codeunit.al`, both profiles, to plain C#. It keeps AL
1-based indexing and statement order line for line, so the output bytes should match the AL, and it lets parser settings be
measured off-BC before they are ported back. Counters feed the README AL time model (ms per raw MB).

`Program.cs` compares it with GZip (`GZipStream`, the same engine as BC `Data Compression`.GZipCompress; `gz-opt` = BC
default) and with reference `zstd` CLI levels. Every AL frame is checked with `zstd -d`.

```
dotnet build -c Release bench/ZstdAlPort
dotnet bench/ZstdAlPort/bin/Release/net8.0/ZstdAlPort.dll <file or dir>... [--levels Fast,Medium,Heavy]
    [--profiles General,ColumnData] [--no-verify] [--no-ref]
```

Columns `al-<Level>` use the General profile and `al-<Level>/C` the ColumnData profile.

Parameter sweeps (`Tune.cs`): one configuration per line, `name Level[:Profile] key=value...`. The keys are the `Tuning`
fields: the AL `SetTuning` parameters plus experiment knobs (`RepChecks`, `SpeedMode`, `DfShortMul`, `Ldm`). Every
configuration runs on every file set. Each set reports the total size vs total GZip, the mean per-file size vs GZip (small
files weigh the same as large ones), and the AL time model estimate.

```
dotnet bench/ZstdAlPort/bin/Release/net8.0/ZstdAlPort.dll --tune configs.txt --set Small=dir1 --set Large=dir2
# configs.txt :
#   medium-general Medium
#   medium-column  Medium:ColumnData
#   medium-depth32 Medium SearchDepth=32 SkipRunInsert=1
```

`PERFILE=1` prints each file's size vs GZip, and `ENTROPY=1` prints the literals and sequences size vs the order-0 ideal.

The ColumnData profile was checked byte for byte against the first version of this port (168 frames, 3 levels).

Requirements: .NET 8 SDK; `zstd` on the PATH for verification and reference sizes (optional).

## bzip2 thought experiment (`Bz2Al.cs`)

`--bzip2 <file or dir>... [--iters N] [--stmt-ns X]` runs a bzip2 encoder and decoder written as they would be in pure AL
(no bit operators, arrays of at most 1M elements, 2 bytes per append), counting the AL statements each stage would run.
Streams are checked with `bzip2 -d` and with the port's own decoder. On the 54 MB corpus at 20 ns / statement: size
-22.1 % vs GZip (zstd Heavy -13.3 %), encode ~3.3 s/MB (SA-IS 1.45, MTF 0.77), decode ~0.8 s/MB, about 12x / 20x
slower than the zstd codec.

## BWT-lite experiments

- `--bwtlite <files>`: size-only comparison of ways to code a BWT column (no MTF, bounded move-to-front of the last K
  bytes, full MTF, 16-bit symbols).
- `--bwtl <files> [--k K] [--iters N] [--maxlen M]` (`BwtLiteAl.cs`): an own-format BWT codec written AL-style, with an
  encoder, a decoder and a round-trip check. It uses a sentinel BWT (no rotation search, RLE1 or CRC), runs and a K-entry
  recency list, and bzip2 multi-table Huffman. The decoder fills Next during decoding (1 statement per run byte) and walks
  it 2 bytes per append. Corpus result (K = 16): -21.4 % vs GZip (bzip2 -22.1 %, zstd Heavy -13.3 %), encode ~2.1 s/MB,
  decode ~0.34 s/MB (0.17-0.43 on compressible files).
