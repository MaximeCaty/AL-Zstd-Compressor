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
