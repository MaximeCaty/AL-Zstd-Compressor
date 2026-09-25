# AL Zstandard Compression 

Pure-AL zstd codec (RFC 8878)

**Why:** in the cloud, AL only has `GZipCompress` (codeunit "Data Compression").
This codec writes standard zstd frames, **10-30 % smaller than GZip**. The frames can be read by any zstd
decoder, including windows 11 builtin file explorer.

Decomprssor support any zstd produced file up to level up 19.
 - Does not support window above 16 MB (zstd level 20+, option --long or any windowLog above 24)
 - Does not support custom trained dictionnary

## Public API

| Procedure | Purpose |
|---|---|
| `Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO ZSTD Level")` | Writes one zstd frame (content size set, no checksum, no dictionary, window up to 16 MB), with the `General` profile. |
| `Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO ZSTD Level"; Profile: Enum "TOO ZSTD Profile")` | Same, with an explicit profile: `General` (any file) or `ColumnData` (column-oriented table exports). |
| `Decompress(var Source: InStream; var Target: OutStream)` | Reads any standard stream: concatenated or skippable frames, raw, RLE or compressed blocks, every FSE table mode. Does not verify the checksum, so the caller checks integrity. |
| `SetTuning(...)` | Benchmarks only. Overrides the parser settings for the **next** `Compress` call; `-1` keeps the level default. |

```al
var
    Zstd: Codeunit "TOO ZSTD Data Compression";
begin
    Zstd.Compress(InStr, OutStr, Enum::"TOO ZSTD Level"::Medium);                                         // any file
    Zstd.Compress(InStr, OutStr, Enum::"TOO ZSTD Level"::Medium, Enum::"TOO ZSTD Profile"::ColumnData);   // table exports
    Zstd.Decompress(ZInStr, OutStr);
```

The profile picks the parser settings behind each level. Both write standard frames, and `Decompress` reads either.

- **ColumnData**: the settings tuned on binary, column-oriented exports of SQL table data (table below). On general files
  it is weak on small inputs: +0 to +4 % over GZip below 64 KB.
- **General** (default): tuned on general files (JSON, XML, CSV, text, source code, PDF, a binary database, enwik8). The
  best hashed length depends on the input size, not its type:
  - up to 64 KB: 4-byte hash chains; up to 256 KB: 5-byte. Lazy parse at every level with a deep search (Fast 8, Medium
    32, Heavy 128 candidates and 2 lazy steps), no LDM. A small input costs little in absolute time.
  - above 256 KB: the ColumnData strategies with a 4-byte short hash (Fast), 16 candidates and 3 repeat checks (Medium),
    24 candidates and 2 lazy steps (Heavy): about +6 to +10 % encode time.

Size vs GZip on general files, General profile :

| Input | Fast | Medium | Heavy |
|---|---|---|---|
| up to 64 KB | -0.7 % | -2.0 % | -2.4 % |
| 64-256 KB | -3.7 % | -5.5 % | -6.2 % |
| above 256 KB | -3.8 % | -12.4 % | -13.3 % |
| enwik8 (100 MB) | -3.9 % | -11.8 % | -12.5 % |

PDFs whose streams are already deflated gain 0-2 % at any setting. Below 32 KB, even reference zstd -15 is only ~3 % smaller
than GZip.

**Limits:**
- The whole input is held in memory as Text (2 bytes per byte), so chunk large inputs before calling.
- Chains reach back 1 MB, because AL arrays cap at 1M elements. Only LDM finds matches further back, up to the 16 MB window.
- `SingleInstance`: the tables live for the whole session. Output does not depend on earlier calls: stale match-table entries are
  rejected, and the LDM bucket rotation (`LdmNext`) is reset on each call that uses LDM.

## Architecture

```
Compress: ReadInput (Latin-1 text) -> frame header -> blocks of 128 KB:
    RLE probe ─► RLE block
    TryCompressedBlock:
        FindSequences ─► ParseDoubleFast | ParseLazy | ParseWithLdm (FindLdmMatches + lazy in the gaps)
        literals      ─► TryLiteralsHuffman (1 or 4 streams, FSE-coded weights) | WriteLiteralsRaw
        sequences     ─► ChooseTable per LL/OF/ML (predefined / RLE / new FSE / repeat) -> WriteSequences
        not smaller than raw? ─► raw block (repeat offsets and tables are committed only for emitted blocks)
    -> OutTB -> one DotNet_StreamWriter write

Decompress: DecodeFrame loop -> blocks -> DecodeLiterals (Huffman: 1-symbol + 2-symbol tables)
            -> DecodeSequences (FSE, backward bit reader) -> window flushed past WinSize + 4 MB and at frame end
```

The codeunit is organised in `#region`s, one per direction and stage. The header comment of each region records its stage (0-9)
and the reasoning behind it.

## Performance: working at the AL cost frontier

Costs measured on BC (micro benchmarks, user runs):

| Operation | Cost |
|---|---|
| Procedure call (local or external) | **~450 ns** |
| Integer / BigInteger math | 1-2 ns |
| Array read | ~4.5 ns |
| `Text[i]` | ~7.7 ns |
| `List.Get` | ~35 ns |
| `TextBuilder.Append` (per call) | 68-76 ns |
| `Substring` compare, 16 / 64 / 256 B | 76 / 149 / 194 ns |
| Latin-1 read (`DotNet_StreamReader`) | 13 ns/B |
| Extra statement or branch | costs more than the math it guards |

BC compiles each AL statement into C# with a hit counter (`StmtHit`), and conditions do not short-circuit. **The main lever is fewer
statements, conditions and calls, not cleverer math.**

Techniques used:

1. **Bytes as Latin-1 chars.** `ReadToEnd` with ISO-8859-1 reads the input once, and the char code equals the byte. Output goes to a
   `TextBuilder` and is written once. There is no per-byte `InStream.Read`.
2. **Bulk copies.** Literal runs and matches are copied with `Text.Substring` and `TB.ToText` (~1 ns/B on long runs). `PairTbl`
   (65 536 × `Text[2]`) means one `Append` per 2 bitstream bytes. `Empty.PadRight(N, C)` is used instead of `PadStr`, and `.Substring`
   instead of `CopyStr`, because the .NET Text methods are faster.
3. **No calls in hot loops.** Helpers tagged `// HOT-INLINE` (`EmitSequence`, `FseEncode`, `AddBits`, `ReadBitsBack`) have inline
   copies in the parse, encode and decode loops, because a call costs ~10× the work it wraps.
4. **SingleInstance, with all state in globals.** Tables are allocated once per session, and hot code never crosses a codeunit boundary.
5. **Fewer statements per byte.**
   - Chain insertion went from 6 statements to 4: the hash is inlined, and Char arithmetic is folded (AL allows it).
   - The LDM rolling hash went from 3 statements to 2.
   - One pass builds the sequence histograms.
   - `X mod M` beats `if X >= M then X -= M`.
   - Reading an array twice beats caching the value in a variable.
6. **Guard char.** One char is appended past the input, so match loops can compare past `BlockEnd` without a bounds test.
7. **Match extension in steps.** Matches extend per byte up to 16, then by 64-byte `Substring` compares, then by 256-byte compares
   after a 64-byte hit, then per byte again. Bulk compares lose when candidates mismatch early, so tune this step pattern on real
   data, not on equal-string benchmarks.
8. **Match tables are never cleared per call.** Entries store `position + 1 + PosBase`, so entries from earlier calls read as negative
   positions. The ~3.6M entries are cleared only when PosBase nears Integer overflow. An export compresses many small files.
9. **Lookup tables instead of arithmetic.** `Pow2B` (2^k), `HBTbl` (highbit), `Log2Q8`, and the LL/ML code tables. Bit containers are
   `BigInteger`: a 56-bit backward reader and a forward accumulator.
10. **Cheap early rejects.**
    - RLE blocks are probed with 3 chars before the full compare.
    - Chain candidates are rejected on the byte just past the best length.
    - Fast skips ahead `1 + run / 128` in literal runs.
    - A prefix compare runs only when the best length is at least 16.
11. **Settings chosen by measurement.**
    - MinMatch 6 beats 5 on column exports, in both size and time.
    - Heavy uses `MaxInsertLen 128`: same size, -1.4 % time.
    - Medium uses lazy depth 1, search depth 8 and `SkipRunInsert`.

**Limits reached:**
- The parameter frontier is exhausted: LDM sampling, skip speed, good/nice/max lazy and rep checks all cost size or save less than 3 %.
- Multi-session compression was rejected: the session, SQL and commit overhead is too high.
- 10 MB/s or more on a single session at the Medium ratio is out of reach.
- Time model fitted on 7 BC runs (±2.4 %), with counters in thousands per raw MB:
  `ms/MB ≈ 45 + 0.079·inserts + 0.364·positions + 0.041·candidates + 0.0076·bytes`.

**Benchmark rules:**
- Time N calls as one block. Timing each call with `CurrentDateTime` was ~20 % off.
- Warm procedures before timing: later loops in a procedure called only once run ~2.5× slower.
- Expect ±4-5 % noise between runs.

**Verification:** every speed pass was checked byte-for-byte against a reference copy and with `zstd -t` / `zstd -d` (zstd 1.5.7 CLI).
