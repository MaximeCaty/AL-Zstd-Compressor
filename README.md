# AL Advanced Compression

Pure-AL compression codecs for Business Central (SaaS safe: no custom DotNet, no file system). In the cloud, AL only
has GZip (codeunit "Data Compression"). These codecs write standard formats that any tool can read, and they compress
better than GZip.

| Folder | Codec | Objects |
|---|---|---|
| `zstd/` | Zstandard (RFC 8878) | codeunit 51150 "TOO ZSTD Data Compression", enums 51150 "TOO ZSTD Level", 51151 "TOO ZSTD Profile" |
| `brotli/` | Brotli (RFC 7932) | codeunit 51160 "TOO Brotli Data Compression", enums 51160 "TOO Brotli Level", 51161 "TOO Brotli Profile" |
| `bench/` | C# ports, benchmarks and the AL → C# transpiler used to test the codecs off-BC | |

## API

Both codeunits have the same API. The profile is `General` (any file, the default) or `ColumnData` (binary
column-oriented table exports).

```al
Zstd.Compress(InStr, OutStr, Enum::"TOO ZSTD Level"::Medium [, Enum::"TOO ZSTD Profile"::ColumnData]);
Zstd.Decompress(ZInStr, OutStr);
Brotli.Compress(InStr, OutStr, Enum::"TOO Brotli Level"::Heavy [, Enum::"TOO Brotli Profile"::ColumnData]);
Brotli.Decompress(BrInStr, OutStr);
```

- **Levels:** Fast = double-fast parse; Medium = lazy parse with speed limits + long-distance matching; Heavy = full lazy
  search + long-distance matching. Both codecs use the same parser, so each level finds the same matches in both.
- **zstd `Decompress`:** reads any zstd stream up to level 19. It has no window above 16 MB (`--long`, level 20+), no
  trained dictionary, and it doesn't verify the checksum.
- **Brotli `Decompress`:** reads any Brotli stream, with windows up to 16 MB. For streams from other encoders that use
  Brotli's static dictionary, add the resource to `app.json`: `"resourceFolders": [ "resources" ]`, with
  `brotli/resources/brotli-dictionary.bin` (runtime 12.0+). Streams from this encoder never need it.

## Comparison

Size vs GZip on 54 MB of general files (JSON, XML, CSV, text, source code, PDF, a binary database and enwik8), General
profile:

| | Fast | Medium | Heavy | Binary DB (Heavy) | Files ≤ 256 KB (Heavy) |
|---|---|---|---|---|---|
| zstd | -4.1 % | -12.5 % | -13.5 % | -9.9 % | ~-3 % |
| Brotli | -6.7 % | -14.9 % | -15.9 % | -15.6 % | ~-6 % |

AL time per MB of the full-size files of this corpus (53 MB), General profile, from the transpiled codeunits
(`bench/AlTranspile`: 20 ns per AL statement, 450 ns per call). Absolute times depend on the data and on the BC
environment (on the BC profile of a Brotli roundtrip, BC ran at ~0.85x this model), so compare the cells with each other:

| | Encode Fast | Encode Medium | Encode Heavy | Decode |
|---|---|---|---|---|
| zstd | ~250 ms | ~515 ms | ~625 ms | ~110-125 ms |
| Brotli | ~275 ms | ~540 ms | ~650 ms | ~85-95 ms |

- **zstd:** its frames open in Windows Explorer and the zstd CLI.
- **Brotli:** 2-5 points smaller, most of all on binary and structured data, because it codes each literal with the
  context of the 2 previous bytes. It encodes ~5 % slower than zstd and decodes ~20 % faster. Its streams open with .NET
  `BrotliStream`, browsers and the brotli CLI.
- Every level is slower than GZip: these codecs trade speed for size.

## Limits and design notes

- The whole input is held in memory as Text (2 bytes per byte), so chunk very large inputs.
- Hash chains reach back 1 MB, because AL arrays cap at 1M elements. Long-distance matching finds matches up to the 16 MB
  window.
- `SingleInstance`: tables live for the session, but output never depends on earlier calls.
- AL cost frontier, measured on BC:

  | Operation | Cost |
  |---|---|
  | procedure call | ~450 ns |
  | statement | ~20 ns |
  | array read | ~4.5 ns |
  | `Text[i]` | ~7.7 ns |
  | `TextBuilder.Append` | ~70 ns |

  So the hot loops keep inline copies of helpers (`// HOT-INLINE`), bytes live as Latin-1 chars, copies are bulk
  `Substring` / `ToText`, bits go 2 bytes per `Append`, and match extensions compare 4 bytes per statement against 4
  guard chars past the input. `bench/AlTranspile` counts the statements of each procedure and AL line to find what to
  cut; its ranking matches the BC profiler.
- The parser settings of each level and profile, and the measurements behind them, are documented in the codeunits
  (`ApplyLevel`, `ApplyGeneralProfile`).

## Testing

- **zstd:** every speed pass was checked byte for byte against a reference copy and with `zstd -t` / `zstd -d`; the C#
  port (`bench/ZstdAlPort`) round-trips its corpus through `zstd -d`. The codeunit also runs transpiled to C#
  (`bench/AlTranspile/zstd/run.sh`): its frames are checked with `zstd -d`, and the AL `Decompress` reads ~300 real zstd
  frames (levels 1-19).
- **Brotli:** the AL codeunit is transpiled to C# (`bench/AlTranspile/run.sh`). Its streams are decoded by .NET
  `BrotliDecoder` and by the AL `Decompress`, and the AL `Decompress` reads ~300 real Brotli streams (q1-q11, windows
  16-24). It was profiled in BC on a 9.6 MB MySQL dump roundtrip.
- `--hashes` (both harnesses) compares the bytes written by two versions: speed passes that must not change the output
  are checked on ~560 streams per codec.
