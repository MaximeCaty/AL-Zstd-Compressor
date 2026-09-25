# AL zstd encoder: C# port and benchmark

`ZstdAlPort/ZstdAlEncoder.cs` ports the **Compress** side of `TOOZSTDDataCompression.Codeunit.al` to plain C#. It keeps AL
1-based indexing and statement order line for line, so the output bytes should match the AL, and it lets parser settings be
measured off-BC before they are ported back. Counters feed the README AL time model (ms per raw MB).

`Program.cs` compares it with GZip (`GZipStream`, the same engine as BC `Data Compression`.GZipCompress; `gz-opt` = BC
default) and with reference `zstd` CLI levels. Every AL frame is checked with `zstd -d`.

```
dotnet build -c Release bench/ZstdAlPort
dotnet bench/ZstdAlPort/bin/Release/net8.0/ZstdAlPort.dll <file or dir>... [--levels Fast,Medium,Heavy] [--no-verify] [--no-ref]
```

Requirements: .NET 8 SDK; `zstd` on the PATH for verification and reference sizes (optional).
