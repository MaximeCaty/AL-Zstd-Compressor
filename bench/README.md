# AL zstd encoder: C# port and benchmark

`ZstdAlPort/ZstdAlEncoder.cs` ports the **Compress** side of `zstd/TOOZSTDDataCompression.Codeunit.al`, both profiles, to plain C#. It keeps AL
1-based indexing and statement order line for line, so the output bytes should match the AL, and it lets parser settings be
measured off-BC before they are ported back. Counters feed the AL time model of the root README (ms per raw MB).

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

## Brotli estimate (`--brotli`, `BrotliLit.cs`)

Re-codes the literals of the AL zstd parse with brotli-style literal context modeling: 64 contexts from the 2
previous bytes, 4 modes, greedy clustering into trees. It reports the size that would give, plus the literals and
commands per byte that drive the AL decoder cost model. Corpus result (Heavy parse): zstd -13.3 % vs GZip, with
context-modeled literals -15.3 % (binary DB -9.9 → -14.9 %, files ≤ 256 KB -3.3 → -5.7 %). Real brotli q9 reaches -17.9 %;
the rest is its static dictionary and command coding.

## AL-style Brotli (`BrotliAl.cs`, `--brotli-al`)

A Brotli (RFC 7932) encoder and decoder written AL-style, with statement counts.
- Encoder: the AL zstd parser (`ParseHook`, same matches and parse cost) feeding Brotli commands, in 1 MB meta-blocks.
  Literals use 64 contexts and one of 4 modes, with the contexts clustered into prefix codes; distances use short codes
  from the 4-distance ring. Prefix codes are simple or complex; a meta-block that doesn't beat raw size is stored
  uncompressed.
- Decoder: full RFC 7932, including the static dictionary (`brotli-dictionary.bin`, google/brotli, MIT) and the 121
  transforms (`BrotliData.cs`, generated from google/brotli).
- Checks: our streams decode with .NET `BrotliDecoder`, and our decoder reads .NET `BrotliEncoder` q5 / q9 streams
  (dictionary words and block switches included).

Corpus results (54 MB, Heavy parse): -15.9 % vs GZip (zstd AL -13.3 %, real Brotli q9 -17.9 %). Modelled AL speed:
encode ~385 ms/MB (zstd ~277), decode ~73 ms/MB (zstd ~60, same unit costs). With the Medium parse: -14.9 %, encode
~333 ms/MB.

## AL -> C# transpiler (`AlTranspile/`)

`al2cs.py` turns an AL codeunit into C# that behaves like AL:
- 1-based arrays and Text with bound checks;
- checked Integer arithmetic, and `and` / `or` evaluating both sides;
- stubs for DotNet_StreamReader / Writer, Temp Blob and NavApp.

`run.sh <files>` transpiles `brotli/TOOBrotliDataCompression.Codeunit.al` and tests it. The AL streams are checked with
.NET `BrotliDecoder` and the AL `Decompress`, and the AL `Decompress` also reads real Brotli streams. `--debug-pair A B`
compares a fresh codeunit instance with a reused one, which is how the SingleInstance state bug in the context
clustering was found.

`COUNT=1 AlTranspile/run.sh --profile-run <file> [Level] [Profile]` runs one roundtrip with a counter per AL statement
and per procedure call, and prints each procedure's cost in the AL time model (20 ns per statement, 450 ns per call).
It gives the same ranking as the BC profiler; its absolute times read ~1.5-2x high on the tightest loops.
