# AL Brotli Compression

A pure-AL Brotli codec (RFC 7932), SaaS safe: no custom DotNet and no file system. It writes standard Brotli streams that
.NET `BrotliStream`, browsers and the `brotli` CLI can read, and it reads any Brotli stream.

## Files

| File | Content |
|---|---|
| `TOOBrotliDataCompression.Codeunit.al` | codeunit 51160 "TOO Brotli Data Compression": encoder + decoder |
| `TOOBrotliLevel.Enum.al` | enum 51160 "TOO Brotli Level": Fast, Medium, Heavy |
| `TOOBrotliProfile.Enum.al` | enum 51161 "TOO Brotli Profile": General (default), ColumnData |
| `resources/brotli-dictionary.bin` | Brotli static dictionary (122,784 bytes, from google/brotli, MIT license) |

Renumber the objects if 51160-51161 are already used in your app.

The dictionary is only read by `Decompress`, and only for streams that reference it; streams from this encoder never do.
Declare the resource folder in `app.json` (runtime 12.0+, for `NavApp.GetResource`):

```json
"resourceFolders": [ "resources" ]
```

Without the resource, everything works except decoding a foreign stream that uses dictionary words, which raises an error.

## API

```al
var
    Brotli: Codeunit "TOO Brotli Data Compression";
begin
    Brotli.Compress(InStr, OutStr, Enum::"TOO Brotli Level"::Heavy);                                          // any file
    Brotli.Compress(InStr, OutStr, Enum::"TOO Brotli Level"::Heavy, Enum::"TOO Brotli Profile"::ColumnData);  // table exports
    Brotli.Decompress(BrInStr, OutStr);
```

## Design

- **Parser:** the lazy / double-fast parser of codeunit "TOO ZSTD Data Compression", copied verbatim (same levels,
  profiles, matches and parse cost). Literals stay in the input text, and the match offsets are recorded.
- **Brotli back end:**
  - 1 MB meta-blocks, one block type per category.
  - Literals: 64 contexts of the 2 previous bytes, one context mode per meta-block (chosen on 1 literal in 4), contexts
    clustered into prefix codes.
  - Distances: the 16 short codes against the 4-distance ring, and the implicit last distance.
  - Prefix codes: simple (up to 4 symbols) or complex, with lengths up to 15.
  - A meta-block that doesn't beat its raw size is stored uncompressed.
- **Decoder:** full RFC 7932 (block switching, context maps with RLE / inverse MTF, NPOSTFIX / NDIRECT, dictionary + 121
  transforms, uncompressed and metadata meta-blocks), 8-bit-root prefix tables, 2 literals per `Append`, and a sliding
  output window.
- **Same layout rules as the zstd codec:** SingleInstance, all hot state in globals, `// HOT-INLINE` copies in the hot
  loops, Latin-1 text for the bytes, LSB-first bit I/O 2 bytes per `Append`. AL has no bit operators: shifts use
  `Pow2B`, and the OR of two context parts uses `OrTbl`. Conditions never rely on short-circuit evaluation, since AL
  evaluates both sides of `and` / `or`.

## Results (54 MB of general files: JSON, XML, CSV, text, source, PDF, binary DB, enwik8)

| | Fast | Medium | Heavy |
|---|---|---|---|
| Size vs GZip | -6.7 % | -14.9 % | -15.9 % |
| zstd codec, same parse | -4.1 % | -12.5 % | -13.5 % |

Estimated AL time (C# model, statements x ~20 ns): encode ~385 ms/MB (Heavy) and decode ~73 ms/MB, vs zstd ~277 / ~60
with the same unit costs.

## Testing

The codeunit was checked off-BC by transpiling this AL to C# (`bench/AlTranspile`: 1-based arrays, Text value semantics,
checked Integer arithmetic and AL's full `and` / `or` evaluation):

- 49 files, including empty, 1-3 bytes, random, 2 MB of zeros and 20 MB of enwik8, at all levels and both profiles;
- one SingleInstance codeunit for all calls;
- every stream decoded by .NET `BrotliDecoder` and by the AL `Decompress`;
- the AL `Decompress` also decodes ~190 real Brotli streams (.NET q1 / q5 / q9 / q11), which use dictionary words and
  block switches.

It has not been compiled or run in Business Central yet: build it there first, then round-trip a few files.
