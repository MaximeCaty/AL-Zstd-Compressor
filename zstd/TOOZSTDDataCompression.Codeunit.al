/*
    Pure-AL zStandard codec (RFC 8878), SaaS safe : no custom DotNet, no file system.
    Public API :
    - Compress(Source, Target, Level [, Profile]) : one standard zstd frame (content size, no checksum, no dictionary,
      window up to 16 MB), readable by any zstd decoder. Profile (enum "TOO ZSTD Profile", default General) picks the
      parser settings behind each level (see ApplyLevel) :
      ColumnData : column-oriented table exports. Levels (enum "TOO ZSTD Level") :
        Fast   (-5% over gz)   : zstd levels 3-4 strategy : double fast parse (2 hash tables of 8 and 5 bytes, no chains)
        Medium (-10% over gz)  : zstd levels ~5 + long-distance matching : lazy parse on 6-byte hash chains (8 candidates) with
                                 gzip -6 style limits (speed mode)
        Heavy  (-15% over gz)  : zstd levels ~9 + long-distance matching : full lazy search (6-byte hash, 16 chain candidates,
                                 1 lazy step)
      General : general files (text, JSON, XML, CSV, PDF...). Up to 256 KB : lazy parse at every level on 4-byte (<= 64 KB)
        or 5-byte hash chains, deep search (Fast 8, Medium 32, Heavy 128 candidates + 2 lazy steps), no long-distance
        matching. Larger inputs : ColumnData strategies with a 4-byte short hash (Fast), 16 candidates and 3 repeat checks
        (Medium), 24 candidates and 2 lazy steps (Heavy).
        Size vs gz on general files : Fast -4%, Medium -12%, Heavy -13% (files <= 256 KB : -1 to -7%).
    - Decompress(Source, Target) : any standard zstd stream : concatenated / skippable frames, raw, RLE and compressed
      blocks, Huffman literals, all FSE table modes, windows up to 16 MB ; no dictionary, checksum skipped (the caller
      checks integrity).

    Layout rules :
    - SingleInstance : all hot state and buffers are globals, hot code never crosses a codeunit boundary.
    - Helpers tagged // HOT-INLINE touch only globals ; hot loops carry inline copies (a call costs ~450 ns).
    - Streams touched once : input read once, output written in bulk.
    - Globals shared by both directions (input text, output builder, Latin-1 / constant tables, repeat offsets) are reset
      at the start or end of each Compress / Decompress ; one-time tables (InitLatin1, InitTables) serve both.

    Bytes live as Latin-1 chars (char code = byte) :
    - input : DotNet_StreamReader(ISO-8859-1).ReadToEnd, InText[i] = 13 ns / byte ;
    - output : TextBuilder, runs copied in bulk (Text.Substring / TB.ToText : ~140 ns per 16 B call, ~1 ns / byte on long
      runs), written by DotNet_StreamWriter(ISO-8859-1). Per-byte TextBuilder.Append costs 76 ns : never used on a hot
      path, only header / bitstream bytes are appended one by one (2 per Append through PairTbl).
    - Decompress writes its window once it exceeds WinSize + 4 MB, and at frame end ; Compress writes the frame once.
      ponytail: Compress keeps the whole input in memory, 2 bytes per char ; chunk above that.
    - Compress match tables keep position + 1 + PosBase across calls : entries of earlier calls read as negative
      positions, so the ~3.6M table entries are only cleared when PosBase nears the Integer limit (exports compress many
      files).
    - Compress appends one guard char to InText (InLen unchanged) : match loops compare past BlockEnd by one char
      instead of testing a flag ; match extension = 16 per byte, 64-byte bulk, 256-byte bulk after a 64 hit, per byte.
      Micro bench (codeunit "TOO ZSTD Micro Bench") : a statement / branch costs more than integer math, Substring
      compare 16 B 76 ns, 64 B 149 ns, 256 B 194 ns ; global and local scalars cost the same.
*/
codeunit 51150 "TOO ZSTD Data Compression"
{
    Access = Public;
    SingleInstance = true;

    var
        // ---------- Shared by Compress and Decompress ----------
        // Input : Latin-1 text of the whole stream
        InText: Text;
        InLen: Integer;
        // Output : Compress = frame, Decompress = window (Latin-1 chars)
        OutTB: TextBuilder;
        LitText: Text;
        Empty: Text; // always '' : Empty.PadRight(N, C) = N x C
        CharTbl: array[256] of Text[1];
        Latin1Ready: Boolean;
        // Repeat offsets : Decompress = live history, Compress = committed history (decoder's after the last emitted block)
        Rep1: BigInteger;
        Rep2: BigInteger;
        Rep3: BigInteger;
        LLBase: array[53] of Integer; // [53] : shared ParseList signature
        LLBits: array[53] of Integer;
        MLBase: array[53] of Integer;
        MLBits: array[53] of Integer;
        Pow2B: array[64] of BigInteger; // Pow2B[K + 1] = 2^K
        TablesReady: Boolean;
        NormCount: array[256] of Integer; // [S + 1]
        // ---------- Decompress ----------
        InPos: Integer; // 1-based, next byte
        // Output window (Latin-1 chars)
        OutDropped: BigInteger; // frame bytes written and removed from OutTB
        WinSize: BigInteger;
        // Block state
        LitLen: Integer;
        LitPos: Integer;
        TableValid: array[3] of Boolean;
        // Huffman literals : single-symbol table, 2^HufMaxBits cells, kept for treeless blocks of the frame
        HufChar: array[2048] of Text[1];
        HufBits: array[2048] of Integer;
        // 2-symbol table : same window decodes 2 literals when the 2nd code fits in the bits left (0 = single only)
        HufPair: array[2048] of Text[2];
        HufPairBits: array[2048] of Integer;
        HufMaxBits: Integer;
        HufValid: Boolean;
        Weights: array[256] of Integer; // [S + 1]
        RankStart: array[12] of Integer; // [W]
        // Backward bit reader : BrContainer holds the next BrAvail bits (<= 56), bytes loaded from BrPos down to BrStart
        BrContainer: BigInteger;
        BrAvail: Integer;
        BrPos: Integer;
        BrStart: Integer;
        BrOver: Integer;
        // FSE decode tables : 4 slots x 512 cells (1 LL, 2 OF, 3 ML, 4 Huffman weights)
        DSymbol: array[2048] of Integer;
        DNbBits: array[2048] of Integer;
        DBase: array[2048] of Integer;
        DTableLog: array[4] of Integer;
        SymbolNext: array[256] of Integer;
        // ---------- Compress ----------
        BlockTB: TextBuilder; // compressed block body / bit writer target
        LitTB: TextBuilder; // literals of the current block
        // Huffman literals (stage 4)
        LitHist: array[256] of Integer; // [S + 1]
        HufLen: array[256] of Integer;
        HufCode: array[256] of Integer;
        HufWeight: array[256] of Integer;
        HufMax: Integer;
        LeafSym: array[256] of Integer;
        NodeW: array[512] of Integer;
        NodeParent: array[512] of Integer;
        NodeAlive: array[512] of Boolean;
        PairTbl: array[65536] of Text[2]; // [Lo + Hi * 256 + 1] = 2 bytes, low first : one Append per 2 bitstream bytes
        MaxStage: Integer;
        WindowLog: Integer;
        WindowSize: Integer;
        // Match finder / block
        // Stage 6 hash chains + lazy parse
        Head: array[524288] of Integer; // 19-bit hash -> last position + 1
        Chain: array[1000000] of Integer; // position mod 1M -> previous position + 1 with the same hash
        NextIns: Integer; // next position to insert in the chains
        PosBase: Integer; // match tables store position + 1 + PosBase (see header)
        InsV: BigInteger; // 4 bytes at InsVPos (rolling, stage 9)
        InsVPos: Integer;
        SeqAnchor: Integer; // first position not yet covered by a sequence
        FBLen: Integer;
        FBOff: Integer;
        FBGain: Integer;
        SearchDepth: Integer;
        LazyDepth: Integer;
        DoubleFast: Boolean; // stage 9 : double fast parse instead of chains + lazy (different output)
        DfLong: array[524288] of Integer; // 8-byte hash -> position + 1
        DfShort: array[524288] of Integer; // 5-byte hash -> position + 1
        SpeedMode: Boolean; // stage 9 : skip-ahead in literal runs + gzip -6 style limits (max_lazy 32, good 8, nice 128, max_insert 32)
        // Lazy parse settings (ApplyLevel, overridable once by SetTuning) ; 0 = limit off
        MinMatch: Integer; // hashed bytes = shortest chain match (repeat matches stay >= 4)
        HashMul: BigInteger; // 256^(MinMatch - 1) : rolling hash value, new byte weight
        LdmMinInput: Integer; // long-distance matching only when InLen > this
        MaxInsertLen: Integer; // a longer match only indexes its last MaxInsertLen / 4 positions (gzip max_insert_length)
        MaxLazyLen: Integer; // no lazy step after a match this long (gzip max_lazy)
        NiceLen: Integer; // a match this long ends the chain search (gzip nice_length)
        SkipRunInsert: Boolean; // speed mode skip-ahead also skips indexing the skipped positions (zstd fast)
        RepCheckCount: Integer; // repeat offsets tried per lazy search : 1 (zstd lazy speed mode) or 3
        DfShortMul: BigInteger; // double fast short hash : 2^32 = 5 bytes (VS + low byte of VL), 0 = 4 bytes (VS only)
        TuneActive: Boolean;
        TuneMinMatch: Integer;
        TuneSearchDepth: Integer;
        TuneLazyDepth: Integer;
        TuneLdmMinInput: Integer;
        TuneMaxInsertLen: Integer;
        TuneMaxLazyLen: Integer;
        TuneNiceLen: Integer;
        TuneSkipRunInsert: Boolean;
        HBTbl: array[1024] of Integer; // [V] = highbit(V) = floor(log2 V)
        // Stage 7 long-distance matcher : 131 072 buckets x 4 entries, rolling hash constant 257^63 mod 2^31 - 1
        LdmPos: array[524288] of Integer; // span start position + 1
        LdmTag: array[524288] of Integer;
        LdmNext: array[131072] of Integer; // next entry to overwrite in the bucket
        Gear: array[256] of Integer; // gear hash table : 31-bit pseudo-random value per byte (fixed seed)
        LdmCount: Integer;
        LdmStart: array[2100] of Integer;
        LdmLen: array[2100] of Integer;
        LdmOff: array[2100] of Integer;
        LitCount: Integer;
        NbSeq: Integer;
        SeqLL: array[44000] of Integer;
        SeqML: array[44000] of Integer;
        SeqOfv: array[44000] of Integer; // offset value as read by the decoder : repeat code 1..3 or offset + 3
        SeqLLCode: array[44000] of Integer;
        SeqMLCode: array[44000] of Integer;
        SeqOFCode: array[44000] of Integer;
        LLCodeTbl: array[64] of Integer; // [LL + 1] for LL < 64
        MLCodeTbl: array[128] of Integer; // [ML - 3 + 1] for ML - 3 < 128
        // Repeat offsets (stage 5) : committed history (Rep*) = decoder's after the last emitted block ; PRep* = block draft
        PRep1: Integer;
        PRep2: Integer;
        PRep3: Integer;
        // Sequence tables (stage 5) : Slot* = current block choice, Com* = decoder's current table (repeat mode source)
        SlotMode: array[3] of Integer;
        SlotMax: array[3] of Integer;
        SlotTL: array[3] of Integer;
        SlotRleSym: array[3] of Integer;
        SlotNorm: array[192] of Integer; // 3 slots x 64
        ComValid: array[3] of Boolean;
        ComRle: array[3] of Boolean;
        ComMax: array[3] of Integer;
        ComTL: array[3] of Integer;
        ComNorm: array[192] of Integer;
        Log2Q8: array[1024] of Integer; // [X] = log2(X) x 256
        // Bit writer
        BwAcc: BigInteger;
        BwCount: Integer;
        // FSE encode tables : 4 slots x 512 states, 4 slots x 64 symbols (1 LL, 2 OF, 3 ML, 4 Huffman weights)
        CState: array[2048] of Integer;
        DeltaNbBits: array[256] of Integer;
        DeltaFindState: array[256] of Integer;
        CTableLog: array[4] of Integer;
        HistCount: array[256] of Integer; // [S + 1]
        SeqHist: array[192] of Integer; // [(slot - 1) x 64 + code + 1] : LL, OF, ML code histograms of the block
        Cumul: array[257] of Integer;
        TableSymbol: array[512] of Integer;
        CorruptErr: Label 'The zstd data is corrupted or not supported.', Comment = 'Les données zstd sont corrompues ou non supportées.';
        SettingsErr: Label 'Invalid zstd compression settings.', Comment = 'Paramètres de compression zstd invalides.';
        PlatformErr: Label 'The zstd codec cannot run on this platform.', Comment = 'Le codec zstd ne peut pas fonctionner sur cette plateforme.';
        LLBaseTok: Label '0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,18,20,22,24,28,32,40,48,64,128,256,512,1024,2048,4096,8192,16384,32768,65536', Locked = true;
        LLBitsTok: Label '0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,2,2,3,3,4,6,7,8,9,10,11,12,13,14,15,16', Locked = true;
        MLBaseTok: Label '3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,37,39,41,43,47,51,59,67,83,99,131,259,515,1027,2051,4099,8195,16387,32771,65539', Locked = true;
        MLBitsTok: Label '0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,2,2,3,3,4,4,5,7,8,9,10,11,12,13,14,15,16', Locked = true;
        LLNormTok: Label '4,3,2,2,2,2,2,2,2,2,2,2,2,1,1,1,2,2,2,2,2,2,2,2,2,3,2,1,1,1,1,1,-1,-1,-1,-1', Locked = true;
        OFNormTok: Label '1,1,1,1,1,1,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,-1,-1,-1,-1,-1', Locked = true;
        MLNormTok: Label '1,4,3,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,-1,-1,-1,-1,-1,-1,-1', Locked = true;
        Writer: Codeunit DotNet_StreamWriter;
        Latin1: Codeunit DotNet_Encoding;
        Reader: Codeunit DotNet_StreamReader;

    /// <summary>
    /// Benchmark only : overrides the lazy parse settings (Medium / Heavy) of the NEXT Compress call only, then the level
    /// defaults apply again. -1 = keep the level default. MinMatch 4..6 (hashed bytes), SearchDepth >= 1 (chain
    /// candidates), LazyDepth 0..2 (0 = greedy), LdmMinInput (long-distance matching only when the input is larger ; 999999 =
    /// only when the chains cannot reach the whole input), MaxInsertLen / MaxLazyLen / NiceLen (0 = off), SkipRunInsert.
    /// Overrides apply on top of the level and profile settings. Any override may change the bytes written (still standard zstd).
    /// </summary>
    procedure SetTuning(NewMinMatch: Integer; NewSearchDepth: Integer; NewLazyDepth: Integer; NewLdmMinInput: Integer; NewMaxInsertLen: Integer; NewMaxLazyLen: Integer; NewNiceLen: Integer; NewSkipRunInsert: Boolean)
    begin
        TuneActive := true;
        TuneMinMatch := NewMinMatch;
        TuneSearchDepth := NewSearchDepth;
        TuneLazyDepth := NewLazyDepth;
        TuneLdmMinInput := NewLdmMinInput;
        TuneMaxInsertLen := NewMaxInsertLen;
        TuneMaxLazyLen := NewMaxLazyLen;
        TuneNiceLen := NewNiceLen;
        TuneSkipRunInsert := NewSkipRunInsert;
    end;

    /// <summary>Compresses Source into one zstd frame written to Target, with the General profile.</summary>
    procedure Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO ZSTD Level")
    begin
        Compress(Source, Target, Level, Enum::"TOO ZSTD Profile"::General);
    end;

    /// <summary>
    /// Compresses Source into one zstd frame written to Target. Profile : General (any file) or ColumnData (column-oriented
    /// table exports, the settings of the company data import / export tool).
    /// </summary>
    procedure Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO ZSTD Level"; Profile: Enum "TOO ZSTD Profile")
    var
        SingleSegment: Boolean;
    begin
        InitTables();
        InitLatin1();
        ReadInput(Source);
        ApplyLevel(Level, Profile); // after ReadInput : the General profile depends on InLen
        // guard char past the input (InLen unchanged) : match loops read one char past BlockEnd without a bound test
        InText += CharTbl[1];
        // match tables : stale entries of earlier calls are negative after the PosBase shift ; clear only near overflow
        if PosBase > 2000000000 - InLen then begin
            Clear(Head);
            Clear(Chain);
            Clear(DfLong);
            Clear(DfShort);
            Clear(LdmPos);
            Clear(LdmTag);
            Clear(LdmNext);
            PosBase := 0;
        end;
        // LDM bucket rotation from slot 0 : stale entries are rejected, but their slot order broke ties -> output depended on
        // earlier calls of the session. Cleared only when LDM runs (131 072 entries).
        if (MaxStage >= 7) and (InLen > LdmMinInput) then
            Clear(LdmNext);
        Clear(OutTB);
        NextIns := 0;
        InsVPos := -1;
        Rep1 := 1;
        Rep2 := 4;
        Rep3 := 8;
        Clear(ComValid);
        WindowSize := Pow2B[WindowLog + 1];
        SingleSegment := InLen <= WindowSize;
        WriteFrameHeader(SingleSegment);
        if SingleSegment or (WindowSize > 131072) then
            WriteBlocks(131072)
        else
            WriteBlocks(WindowSize);
        Latin1.ISO88591();
        Writer.StreamWriter(Target, Latin1);
        Writer.Write(OutTB.ToText());
        Writer.Flush();
        // SingleInstance : free the per-call texts, keep the tables for the next call
        PosBase += InLen + 1;
        InText := '';
        LitText := '';
        Clear(OutTB);
        Clear(BlockTB);
        Clear(LitTB);
    end;

    /// <summary>Decompresses the zstd stream Source into Target.</summary>
    procedure Decompress(var Source: InStream; var Target: OutStream)
    begin
        InitTables();
        InitLatin1();
        ReadInput(Source);
        if InLen = 0 then
            Error(CorruptErr);
        Clear(Writer);
        Latin1.ISO88591();
        Writer.StreamWriter(Target, Latin1);
        while InPos <= InLen do
            DecodeFrame();
        Writer.Flush();
        // SingleInstance : free the per-call texts
        InText := '';
        LitText := '';
        Clear(OutTB);
    end;

    #region Shared (compress + decompress)
    local procedure ReadInput(var Source: InStream)
    begin
        Latin1.ISO88591();
        Reader.StreamReader(Source, Latin1);
        InText := Reader.ReadToEnd();
        InLen := StrLen(InText);
        InPos := 1;
    end;

    /// <summary>Single-char Latin-1 text per byte value (CharTbl[B + 1]) and byte pairs (PairTbl), + one-time platform checks (Latin-1 byte-exact, 1-based ToText, ordinal compare).</summary>
    local procedure InitLatin1()
    var
        TempBlob: Codeunit "Temp Blob";
        Target: OutStream;
        Source: InStream;
        TB: TextBuilder;
        All: Text;
        I: Integer;
        B: Byte;
    begin
        if Latin1Ready then
            exit;
        TempBlob.CreateOutStream(Target);
        for I := 0 to 255 do begin
            B := I;
            Target.Write(B);
        end;
        TempBlob.CreateInStream(Source);
        Latin1.ISO88591();
        Reader.StreamReader(Source, Latin1);
        All := Reader.ReadToEnd();
        if StrLen(All) <> 256 then
            Error(PlatformErr);
        for I := 1 to 256 do
            CharTbl[I] := All.Substring(I, 1);
        for I := 0 to 65535 do
            PairTbl[I + 1] := CharTbl[I mod 256 + 1] + CharTbl[I div 256 + 1];
        TB.Append('abc');
        if TB.ToText(2, 1) <> 'b' then
            Error(PlatformErr);
        // bulk compares (CopyStr = CopyStr) must be ordinal : a culture compare ignores NUL / soft hyphen, folds case
        if All.Substring(2, 1) <> CharTbl[2] then
            Error(PlatformErr);
        if (CharTbl[98] + CharTbl[174] + CharTbl[99] = CharTbl[98] + CharTbl[99] + CharTbl[174]) or
           (CharTbl[98] + CharTbl[1] + CharTbl[99] = CharTbl[98] + CharTbl[99] + CharTbl[1]) or
           (CharTbl[98] = CharTbl[66])
        then
            Error(PlatformErr);
        Latin1Ready := true;
    end;

    local procedure ParseList(Csv: Text; var Values: array[53] of Integer)
    var
        V: Text;
        I: Integer;
    begin
        foreach V in Csv.Split(',') do begin
            I += 1;
            Evaluate(Values[I], V);
        end;
    end;

    local procedure InitTables()
    var
        M: BigInteger;
        LcgState: BigInteger;
        I: Integer;
        K: Integer;
        Frac: Integer;
        Code: Integer;
    begin
        if TablesReady then
            exit;
        Pow2B[1] := 1;
        for I := 2 to 63 do
            Pow2B[I] := Pow2B[I - 1] * 2;
        ParseList(LLBaseTok, LLBase);
        ParseList(LLBitsTok, LLBits);
        ParseList(MLBaseTok, MLBase);
        ParseList(MLBitsTok, MLBits);
        HBTbl[1] := 0;
        for I := 2 to 1024 do
            HBTbl[I] := HBTbl[I div 2] + 1;
        // gear table : high bits only of a fixed-seed LCG (its low bits have short periods)
        LcgState := 12345;
        for I := 1 to 256 do begin
            LcgState := (LcgState * 1103515245 + 12345) mod 2147483648L;
            Code := LcgState div 32768; // top 16 of 31 bits
            LcgState := (LcgState * 1103515245 + 12345) mod 2147483648L;
            Gear[I] := Code * 32768 + LcgState div 65536; // + top 15 bits : 31-bit value
        end;
        // log2(X) x 256 for cost estimates : integer part = highbit, 8 fraction bits by repeated squaring of the mantissa
        for I := 1 to 1024 do begin
            Code := HighBit(I);
            M := I * 65536L div Pow2B[Code + 1];
            Frac := 0;
            for K := 1 to 8 do begin
                M := M * M div 65536;
                Frac *= 2;
                if M >= 131072 then begin
                    Frac += 1;
                    M := M div 2;
                end;
            end;
            Log2Q8[I] := Code * 256 + Frac;
        end;
        // code lookup for small values : largest code whose baseline <= value
        Code := 0;
        for I := 0 to 63 do begin
            while (Code < 35) and (LLBase[Code + 2] <= I) do
                Code += 1;
            LLCodeTbl[I + 1] := Code;
        end;
        Code := 0;
        for I := 0 to 127 do begin
            while (Code < 52) and (MLBase[Code + 2] - 3 <= I) do
                Code += 1;
            MLCodeTbl[I + 1] := Code;
        end;
        TablesReady := true;
    end;

    local procedure HighBit(Value: Integer) Result: Integer
    begin
        while Value >= 2 do begin
            Value := Value div 2;
            Result += 1;
        end;
    end;

    /// <summary>Predefined distributions (RFC 8878 3.1.1.3.2.2) into NormCount. Kind 1 LL, 2 OF, 3 ML.</summary>
    local procedure SetPredefinedNorm(Kind: Integer; var MaxSymbol: Integer; var TableLog: Integer)
    var
        Values: List of [Text];
        V: Text;
        S: Integer;
    begin
        case Kind of
            1:
                begin
                    Values := LLNormTok.Split(',');
                    TableLog := 6;
                end;
            2:
                begin
                    Values := OFNormTok.Split(',');
                    TableLog := 5;
                end;
            3:
                begin
                    Values := MLNormTok.Split(',');
                    TableLog := 6;
                end;
        end;
        MaxSymbol := Values.Count() - 1;
        S := 0;
        foreach V in Values do begin
            S += 1;
            Evaluate(NormCount[S], V);
        end;
    end;
    #endregion

    local procedure DecodeFrame()
    var
        Magic: BigInteger;
    begin
        Need(4);
        Magic := ReadLE(4);
        if Magic = 4247762216L then // 0xFD2FB528
            DecodeZstdFrame()
        else
            if Magic div 16 = 25481893 then begin // 0x184D2A5? : skippable frame, 4-byte size + user data
                Need(4);
                SkipBytes(ReadLE(4));
            end else
                Error(CorruptErr);
    end;

    local procedure DecodeZstdFrame()
    var
        FrameWindow: BigInteger;
        ContentSize: BigInteger;
        DictId: BigInteger;
        FrameSize: BigInteger;
        FHD: Integer;
        WD: Integer;
        FcsFlag: Integer;
        FcsSize: Integer;
        DictSize: Integer;
        BlockMax: Integer;
        BlockHeader: Integer;
        BlockType: Integer;
        BlockSize: Integer;
        BlockStart: Integer;
        I: Integer;
        SingleSegment: Boolean;
        HasChecksum: Boolean;
        LastBlock: Boolean;
    begin
        // Frame header descriptor : FCS flag (2) | single segment (1) | unused (1) | reserved (1) | checksum (1) | dict id flag (2)
        Need(1);
        FHD := ReadByte();
        FcsFlag := FHD div 64;
        SingleSegment := (FHD div 32) mod 2 = 1;
        if (FHD div 8) mod 2 = 1 then
            Error(CorruptErr);
        HasChecksum := (FHD div 4) mod 2 = 1;

        // Window descriptor : 2^(10 + exponent) + mantissa / 8 of it
        if not SingleSegment then begin
            Need(1);
            WD := ReadByte();
            FrameWindow := 1;
            for I := 1 to 10 + WD div 8 do
                FrameWindow *= 2;
            FrameWindow += (FrameWindow div 8) * (WD mod 8);
        end;

        case FHD mod 4 of
            1:
                DictSize := 1;
            2:
                DictSize := 2;
            3:
                DictSize := 4;
        end;
        if DictSize > 0 then begin
            Need(DictSize);
            DictId := ReadLE(DictSize);
            if DictId <> 0 then
                Error(CorruptErr);
        end;

        case FcsFlag of
            0:
                if SingleSegment then
                    FcsSize := 1;
            1:
                FcsSize := 2;
            2:
                FcsSize := 4;
            3:
                FcsSize := 8;
        end;
        if FcsSize > 0 then begin
            Need(FcsSize);
            ContentSize := ReadLE(FcsSize);
            if FcsSize = 2 then
                ContentSize += 256;
        end;
        if SingleSegment then
            FrameWindow := ContentSize;
        if FrameWindow > 16777216 then
            Error(CorruptErr);
        WinSize := FrameWindow;
        BlockMax := 131072;
        if FrameWindow < BlockMax then
            BlockMax := FrameWindow;

        // Frame start : empty window, repeat offsets 1 4 8, no table to repeat
        Clear(OutTB);
        OutDropped := 0;
        Rep1 := 1;
        Rep2 := 4;
        Rep3 := 8;
        Clear(TableValid);
        HufValid := false;

        // Blocks : 3-byte header = last (1) | type (2) | size (21)
        repeat
            Need(3);
            BlockStart := InPos;
            BlockHeader := ReadByte();
            BlockHeader += ReadByte() * 256;
            BlockHeader += ReadByte() * 65536;
            LastBlock := BlockHeader mod 2 = 1;
            BlockType := (BlockHeader div 2) mod 4;
            BlockSize := BlockHeader div 8;
            if BlockSize > BlockMax then
                Error(CorruptErr);
            case BlockType of
                0:
                    begin
                        Need(BlockSize);
                        if BlockSize > 0 then
                            OutTB.Append(InText.Substring(InPos, BlockSize));
                        InPos += BlockSize;
                    end;
                1:
                    begin
                        Need(1);
                        OutTB.Append(Empty.PadRight(BlockSize, InText[InPos]));
                        InPos += 1;
                    end;
                2:
                    begin
                        Need(BlockSize);
                        DecodeCompressedBlock(InPos + BlockSize);
                    end;
                3:
                    Error(CorruptErr);
            end;
            SlideWindow();
        until LastBlock;

        // ponytail: checksum skipped, xxHash64 verification is stage 8
        if HasChecksum then
            SkipBytes(4);
        FrameSize := OutDropped + OutTB.Length();
        Writer.Write(OutTB.ToText());
        Clear(OutTB);
        if FcsSize > 0 then
            if FrameSize <> ContentSize then
                Error(CorruptErr);
    end;

    /// <summary>Keeps at most WinSize + 4 MB in OutTB : older bytes are written once and dropped.</summary>
    local procedure SlideWindow()
    var
        Excess: Integer;
    begin
        if OutTB.Length() <= WinSize + 4194304 then
            exit;
        Excess := OutTB.Length() - WinSize;
        Writer.Write(OutTB.ToText(1, Excess));
        OutTB.Remove(1, Excess);
        OutDropped += Excess;
    end;

    #region Decompress : Input
    local procedure Need(Count: BigInteger)
    begin
        if InPos + Count - 1 > InLen then
            Error(CorruptErr);
    end;

    local procedure SkipBytes(Count: BigInteger)
    begin
        Need(Count);
        InPos += Count;
    end;

    local procedure ReadByte() Value: Integer
    begin
        Value := InText[InPos];
        InPos += 1;
    end;

    local procedure ReadLE(Count: Integer) Value: BigInteger
    var
        Mul: BigInteger;
        C: Integer;
        I: Integer;
    begin
        Mul := 1;
        for I := 1 to Count do begin
            C := InText[InPos];
            Value += C * Mul;
            InPos += 1;
            Mul *= 256;
        end;
    end;
    #endregion

    #region Decompress : Compressed block (stage 3)
    local procedure DecodeCompressedBlock(BlockEnd: Integer)
    begin
        DecodeLiterals(BlockEnd);
        DecodeSequences(BlockEnd);
        InPos := BlockEnd;
    end;

    /// <summary>Literals section (RFC 8878 3.1.1.3.1) into LitText : raw, RLE, Huffman compressed, treeless.</summary>
    local procedure DecodeLiterals(BlockEnd: Integer)
    var
        B0: Integer;
        Size: Integer;
    begin
        NeedInBlock(1, BlockEnd);
        B0 := ReadByte();
        if B0 mod 4 >= 2 then begin
            DecodeHuffmanLiterals(B0, BlockEnd);
            exit;
        end;
        case (B0 div 4) mod 4 of
            0, 2:
                Size := B0 div 8;
            1:
                begin
                    NeedInBlock(1, BlockEnd);
                    Size := B0 div 16 + ReadByte() * 16;
                end;
            3:
                begin
                    NeedInBlock(2, BlockEnd);
                    Size := B0 div 16 + ReadByte() * 16;
                    Size += ReadByte() * 4096;
                end;
        end;
        if Size > 131072 then
            Error(CorruptErr);
        if B0 mod 4 = 0 then begin
            NeedInBlock(Size, BlockEnd);
            LitText := '';
            if Size > 0 then
                LitText := InText.Substring(InPos, Size);
            InPos += Size;
        end else begin
            NeedInBlock(1, BlockEnd);
            LitText := Empty.PadRight(Size, InText[InPos]);
            InPos += 1;
        end;
        LitLen := Size;
        LitPos := 1;
    end;

    /// <summary>
    /// Huffman literals (type 2 compressed, 3 treeless) : sizes packed after the 4 type / format bits (10, 10, 14 or 18 bits each),
    /// tree description (type 2 only), then 1 stream (format 0) or a 6-byte jump table + 4 streams.
    /// </summary>
    local procedure DecodeHuffmanLiterals(B0: Integer; BlockEnd: Integer)
    var
        H: BigInteger;
        Size: Integer;
        CompSize: Integer;
        SizeFormat: Integer;
        HeaderBytes: Integer;
        NBits: Integer;
        SectionEnd: Integer;
        I: Integer;
    begin
        SizeFormat := (B0 div 4) mod 4;
        case SizeFormat of
            0, 1:
                begin
                    HeaderBytes := 3;
                    NBits := 10;
                end;
            2:
                begin
                    HeaderBytes := 4;
                    NBits := 14;
                end;
            3:
                begin
                    HeaderBytes := 5;
                    NBits := 18;
                end;
        end;
        NeedInBlock(HeaderBytes - 1, BlockEnd);
        H := B0;
        for I := 1 to HeaderBytes - 1 do
            H += ReadByte() * Pow2B[I * 8 + 1];
        Size := (H div 16) mod Pow2B[NBits + 1];
        CompSize := (H div Pow2B[NBits + 5]) mod Pow2B[NBits + 1];
        if Size > 131072 then
            Error(CorruptErr);
        NeedInBlock(CompSize, BlockEnd);
        SectionEnd := InPos + CompSize;
        if B0 mod 4 = 2 then
            ReadHufTree(SectionEnd)
        else
            if not HufValid then
                Error(CorruptErr);
        DecodeHufStreams(SizeFormat = 0, SectionEnd, Size);
        InPos := SectionEnd;
        LitLen := Size;
        LitPos := 1;
    end;

    /// <summary>
    /// Huffman tree description (RFC 8878 4.2.1) -> single-symbol decode table (HufChar / HufBits, 2^HufMaxBits cells).
    /// Header byte < 128 : FSE-compressed weights (2 interleaved states, table log <= 6) ; >= 128 : (byte - 127) 4-bit weights.
    /// The last weight is implied : it completes the sum of 2^(W - 1) to a power of two.
    /// </summary>
    local procedure ReadHufTree(SectionEnd: Integer)
    var
        Total: Integer;
        Rest: Integer;
        HB: Integer;
        NW: Integer;
        WEnd: Integer;
        TableLog: Integer;
        S1: Integer;
        S2: Integer;
        W: Integer;
        S: Integer;
        U: Integer;
        Len: Integer;
        NB: Integer;
        B: Integer;
        Start: Integer;
        RankCount: array[12] of Integer;
    begin
        if InPos >= SectionEnd then
            Error(CorruptErr);
        HB := ReadByte();
        if HB < 128 then begin
            WEnd := InPos + HB;
            if WEnd > SectionEnd then
                Error(CorruptErr);
            TableLog := ReadNCount(InPos, 255, 6);
            if InPos >= WEnd then
                Error(CorruptErr);
            BuildDTable(4, 255, TableLog);
            BitInitBack(InPos, WEnd - InPos);
            S1 := ReadBitsBack(TableLog);
            S2 := ReadBitsBack(TableLog);
            // alternate the 2 states until a state update reads past the stream start (zstd FSE 2-state decode)
            repeat
                if NW >= 253 then // up to 2 weights per turn + the implied last one : <= 256
                    Error(CorruptErr);
                NW += 1;
                Weights[NW] := DSymbol[1537 + S1];
                S1 := DBase[1537 + S1] + ReadBitsBack(DNbBits[1537 + S1]);
                if BitsLeft() < 0 then begin
                    NW += 1;
                    Weights[NW] := DSymbol[1537 + S2];
                end else begin
                    NW += 1;
                    Weights[NW] := DSymbol[1537 + S2];
                    S2 := DBase[1537 + S2] + ReadBitsBack(DNbBits[1537 + S2]);
                    if BitsLeft() < 0 then begin
                        NW += 1;
                        Weights[NW] := DSymbol[1537 + S1];
                    end;
                end;
            until BitsLeft() < 0;
            InPos := WEnd;
        end else begin
            NW := HB - 127;
            if InPos + (NW + 1) div 2 > SectionEnd then
                Error(CorruptErr);
            for S := 1 to NW do
                if S mod 2 = 1 then begin
                    B := ReadByte();
                    Weights[S] := B div 16;
                end else
                    Weights[S] := B mod 16;
        end;

        // implied last weight
        for S := 1 to NW do begin
            if Weights[S] > 11 then
                Error(CorruptErr);
            if Weights[S] > 0 then
                Total += Pow2B[Weights[S]];
        end;
        if Total = 0 then
            Error(CorruptErr);
        HufMaxBits := HighBit(Total) + 1;
        if HufMaxBits > 11 then
            Error(CorruptErr);
        Rest := Pow2B[HufMaxBits + 1] - Total;
        W := HighBit(Rest) + 1;
        if Pow2B[W] <> Rest then
            Error(CorruptErr);
        NW += 1;
        Weights[NW] := W;

        // canonical table : weight 1 (longest codes) first, symbols in order inside a weight
        for S := 1 to NW do
            if Weights[S] > 0 then
                RankCount[Weights[S]] += 1;
        Start := 0;
        for W := 1 to HufMaxBits do begin
            RankStart[W] := Start;
            Start += RankCount[W] * Pow2B[W];
        end;
        for S := 1 to NW do begin
            W := Weights[S];
            if W > 0 then begin
                Len := Pow2B[W];
                NB := HufMaxBits + 1 - W;
                for U := RankStart[W] + 1 to RankStart[W] + Len do begin
                    HufChar[U] := CharTbl[S];
                    HufBits[U] := NB;
                end;
                RankStart[W] += Len;
            end;
        end;
        // pairs : after the 1st code (NB bits), the next window starts with the U's low (HufMaxBits - NB) bits ;
        // the 2nd symbol is known when its code length fits in them (lookup with the unknown low bits at 0)
        for U := 0 to Pow2B[HufMaxBits + 1] - 1 do begin
            HufPairBits[U + 1] := 0;
            NB := HufBits[U + 1];
            Rest := HufMaxBits - NB;
            if Rest > 0 then begin
                B := (U mod Pow2B[Rest + 1]) * Pow2B[NB + 1];
                if HufBits[B + 1] <= Rest then begin
                    HufPair[U + 1] := HufChar[U + 1] + HufChar[B + 1];
                    HufPairBits[U + 1] := NB + HufBits[B + 1];
                end;
            end;
        end;
        HufValid := true;
    end;

    /// <summary>1 stream (SingleStream) or jump table + 4 streams (Size split in 4 segments of (Size + 3) div 4) into LitText.</summary>
    local procedure DecodeHufStreams(SingleStream: Boolean; SectionEnd: Integer; Size: Integer)
    var
        HufTB: TextBuilder;
        S1: Integer;
        S2: Integer;
        S3: Integer;
        S4: Integer;
        Segment: Integer;
        P: Integer;
    begin
        if SingleStream then
            DecodeHufStream(HufTB, InPos, SectionEnd - InPos, Size, 1)
        else begin
            NeedInBlock(6, SectionEnd);
            S1 := ReadByte();
            S1 += ReadByte() * 256;
            S2 := ReadByte();
            S2 += ReadByte() * 256;
            S3 := ReadByte();
            S3 += ReadByte() * 256;
            S4 := SectionEnd - InPos - S1 - S2 - S3;
            Segment := (Size + 3) div 4;
            if (S4 < 1) or (Size - 3 * Segment < 0) then
                Error(CorruptErr);
            P := InPos;
            DecodeHufStream(HufTB, P, S1, Segment, 1);
            P += S1;
            DecodeHufStream(HufTB, P, S2, Segment, 2);
            P += S2;
            DecodeHufStream(HufTB, P, S3, Segment, 3);
            P += S3;
            DecodeHufStream(HufTB, P, S4, Size - 3 * Segment, 4);
        end;
        LitText := HufTB.ToText();
    end;

    /// <summary>Count symbols from one backward Huffman stream ; hot loop inline (peek HufMaxBits, consume the code length).</summary>
    local procedure DecodeHufStream(var HufTB: TextBuilder; Start: Integer; Size: Integer; Count: Integer; StreamNo: Integer)
    var
        C: Integer;
        Idx: Integer;
        NB: Integer;
        Sh: Integer;
        I: Integer;
    begin
        BitInitBack(Start, Size);
        I := 1;
        while I <= Count do begin
            while (BrAvail <= 48) and (BrPos >= BrStart) do begin
                C := InText[BrPos];
                BrContainer := BrContainer * 256 + C;
                BrPos -= 1;
                BrAvail += 8;
            end;
            if BrAvail >= HufMaxBits then
                Idx := BrContainer div Pow2B[BrAvail - HufMaxBits + 1]
            else
                Idx := BrContainer * Pow2B[HufMaxBits - BrAvail + 1]; // stream end : zero padding
            // 2 literals per lookup / Append when the pair fits (Append ~70 ns per call)
            if (I < Count) and (HufPairBits[Idx + 1] > 0) then begin
                NB := HufPairBits[Idx + 1];
                if NB > BrAvail then
                    Error(CorruptErr);
                HufTB.Append(HufPair[Idx + 1]);
                I += 2;
            end else begin
                NB := HufBits[Idx + 1];
                if NB > BrAvail then
                    Error(CorruptErr);
                HufTB.Append(HufChar[Idx + 1]);
                I += 1;
            end;
            Sh := BrAvail - NB;
            BrContainer := BrContainer mod Pow2B[Sh + 1];
            BrAvail := Sh;
        end;
        if BitsLeft() <> 0 then
            Error(CorruptErr);
    end;

    /// <summary>
    /// Sequences section (RFC 8878 3.1.1.3.2) decoded and executed into OutTB.
    /// Hot loop : bit reads and state updates inline (HOT-INLINE copies of ReadBitsBack), runs copied in bulk.
    /// </summary>
    local procedure DecodeSequences(BlockEnd: Integer)
    var
        OfValue: BigInteger;
        Offset: BigInteger;
        FramePos: BigInteger;
        B0: Integer;
        SeqCount: Integer;
        Modes: Integer;
        N: Integer;
        C: Integer;
        NB: Integer;
        Sh: Integer;
        LLState: Integer;
        OFState: Integer;
        MLState: Integer;
        LLCode: Integer;
        OFCode: Integer;
        MLCode: Integer;
        LL: Integer;
        ML: Integer;
        RepCode: Integer;
        TbLen: Integer;
        Period: Integer;
        Remain: Integer;
        Chunk: Integer;
    begin
        NeedInBlock(1, BlockEnd);
        B0 := ReadByte();
        if B0 < 128 then
            SeqCount := B0
        else
            if B0 < 255 then begin
                NeedInBlock(1, BlockEnd);
                SeqCount := (B0 - 128) * 256 + ReadByte();
            end else begin
                NeedInBlock(2, BlockEnd);
                SeqCount := ReadByte() + 32512;
                SeqCount += ReadByte() * 256;
            end;

        if SeqCount > 0 then begin
            NeedInBlock(1, BlockEnd);
            Modes := ReadByte();
            if Modes mod 4 <> 0 then
                Error(CorruptErr);
            SetupTable(1, Modes div 64, 35, 9, BlockEnd);
            SetupTable(2, (Modes div 16) mod 4, 31, 8, BlockEnd);
            SetupTable(3, (Modes div 4) mod 4, 52, 9, BlockEnd);

            BitInitBack(InPos, BlockEnd - InPos);
            LLState := ReadBitsBack(DTableLog[1]);
            OFState := ReadBitsBack(DTableLog[2]);
            MLState := ReadBitsBack(DTableLog[3]);

            for N := 1 to SeqCount do begin
                LLCode := DSymbol[LLState + 1];
                OFCode := DSymbol[513 + OFState];
                MLCode := DSymbol[1025 + MLState];
                // no per-sequence code range check : SetupTable bounds every symbol (RLE byte checked, predefined and
                // FSE tables built for symbols <= MaxSymbol 35 / 31 / 52)

                // extra bits : OF, ML, LL (each read = refill + div / mod on the container)
                while (BrAvail <= 48) and (BrPos >= BrStart) do begin
                    C := InText[BrPos];
                    BrContainer := BrContainer * 256 + C;
                    BrPos -= 1;
                    BrAvail += 8;
                end;
                if BrAvail < OFCode then
                    Error(CorruptErr);
                Sh := BrAvail - OFCode;
                OfValue := Pow2B[OFCode + 1] + BrContainer div Pow2B[Sh + 1];
                BrContainer := BrContainer mod Pow2B[Sh + 1];
                BrAvail := Sh;

                // no refill : >= 49 bits after the OF refill unless the stream ends, OF <= 31 + ML <= 16
                NB := MLBits[MLCode + 1];
                if BrAvail < NB then
                    Error(CorruptErr);
                Sh := BrAvail - NB;
                ML := MLBase[MLCode + 1] + BrContainer div Pow2B[Sh + 1];
                BrContainer := BrContainer mod Pow2B[Sh + 1];
                BrAvail := Sh;

                while (BrAvail <= 48) and (BrPos >= BrStart) do begin
                    C := InText[BrPos];
                    BrContainer := BrContainer * 256 + C;
                    BrPos -= 1;
                    BrAvail += 8;
                end;
                NB := LLBits[LLCode + 1];
                if BrAvail < NB then
                    Error(CorruptErr);
                Sh := BrAvail - NB;
                LL := LLBase[LLCode + 1] + BrContainer div Pow2B[Sh + 1];
                BrContainer := BrContainer mod Pow2B[Sh + 1];
                BrAvail := Sh;

                // offset : > 3 = new offset, else repeat code (shifted by one when LL = 0)
                if OfValue > 3 then begin
                    Offset := OfValue - 3;
                    Rep3 := Rep2;
                    Rep2 := Rep1;
                    Rep1 := Offset;
                end else begin
                    RepCode := OfValue;
                    if LL = 0 then
                        RepCode += 1;
                    case RepCode of
                        1:
                            Offset := Rep1;
                        2:
                            begin
                                Offset := Rep2;
                                Rep2 := Rep1;
                                Rep1 := Offset;
                            end;
                        3:
                            begin
                                Offset := Rep3;
                                Rep3 := Rep2;
                                Rep2 := Rep1;
                                Rep1 := Offset;
                            end;
                        4:
                            begin
                                Offset := Rep1 - 1;
                                Rep3 := Rep2;
                                Rep2 := Rep1;
                                Rep1 := Offset;
                            end;
                    end;
                end;

                // states : LL, ML, OF (none after the last sequence) ; <= 26 bits, no refill : >= 49 after the LL refill
                // unless the stream ends, LL <= 16
                if N < SeqCount then begin
                    NB := DNbBits[LLState + 1] + DNbBits[1025 + MLState] + DNbBits[513 + OFState];
                    if BrAvail < NB then
                        Error(CorruptErr);
                    NB := DNbBits[LLState + 1];
                    Sh := BrAvail - NB;
                    LLState := DBase[LLState + 1] + BrContainer div Pow2B[Sh + 1];
                    BrContainer := BrContainer mod Pow2B[Sh + 1];
                    BrAvail := Sh;
                    NB := DNbBits[1025 + MLState];
                    Sh := BrAvail - NB;
                    MLState := DBase[1025 + MLState] + BrContainer div Pow2B[Sh + 1];
                    BrContainer := BrContainer mod Pow2B[Sh + 1];
                    BrAvail := Sh;
                    NB := DNbBits[513 + OFState];
                    Sh := BrAvail - NB;
                    OFState := DBase[513 + OFState] + BrContainer div Pow2B[Sh + 1];
                    BrContainer := BrContainer mod Pow2B[Sh + 1];
                    BrAvail := Sh;
                end;

                // execute : LL literals, then ML bytes from Offset back
                if LL > 0 then begin
                    if LitPos + LL - 1 > LitLen then
                        Error(CorruptErr);
                    OutTB.Append(LitText.Substring(LitPos, LL));
                    LitPos += LL;
                end;
                TbLen := OutTB.Length();
                FramePos := OutDropped + TbLen;
                if (Offset < 1) or (Offset > FramePos) or (Offset > WinSize) or (Offset > TbLen) then
                    Error(CorruptErr);
                if Offset >= ML then
                    OutTB.Append(OutTB.ToText(TbLen - Offset + 1, ML))
                else begin
                    // overlap : output is periodic with period Offset, copy doubling chunks of whole periods
                    Period := Offset;
                    Remain := ML;
                    while Remain > 0 do begin
                        Chunk := Period;
                        if Chunk > Remain then
                            Chunk := Remain;
                        OutTB.Append(OutTB.ToText(OutTB.Length() - Period + 1, Chunk));
                        Remain -= Chunk;
                        Period *= 2;
                    end;
                end;
            end;
            if (BrAvail <> 0) or (BrPos >= BrStart) then
                Error(CorruptErr);
        end;

        // last literals
        if LitPos <= LitLen then
            OutTB.Append(LitText.Substring(LitPos, LitLen - LitPos + 1));
    end;

    /// <summary>Table for Slot (1 LL, 2 OF, 3 ML) : 0 predefined, 1 RLE, 2 FSE description, 3 repeat previous.</summary>
    local procedure SetupTable(Slot: Integer; Mode: Integer; MaxSymbol: Integer; MaxTableLog: Integer; BlockEnd: Integer)
    var
        Base: Integer;
        Symbol: Integer;
        PredefMax: Integer;
        TableLog: Integer;
    begin
        Base := (Slot - 1) * 512;
        case Mode of
            0:
                begin
                    SetPredefinedNorm(Slot, PredefMax, TableLog);
                    BuildDTable(Slot, PredefMax, TableLog);
                end;
            1:
                begin
                    NeedInBlock(1, BlockEnd);
                    Symbol := ReadByte();
                    if Symbol > MaxSymbol then
                        Error(CorruptErr);
                    DSymbol[Base + 1] := Symbol;
                    DNbBits[Base + 1] := 0;
                    DBase[Base + 1] := 0;
                    DTableLog[Slot] := 0;
                end;
            2:
                begin
                    TableLog := ReadNCount(InPos, MaxSymbol, MaxTableLog);
                    if InPos > BlockEnd then
                        Error(CorruptErr);
                    BuildDTable(Slot, MaxSymbol, TableLog);
                end;
            3:
                if not TableValid[Slot] then
                    Error(CorruptErr);
        end;
        TableValid[Slot] := true;
    end;

    local procedure NeedInBlock(Count: Integer; BlockEnd: Integer)
    begin
        if InPos + Count > BlockEnd then
            Error(CorruptErr);
    end;
    #endregion

    #region Decompress : Bit readers (stage 2)
    /// <summary>Backward bitstream over InText[Start .. Start + Size - 1] : last byte holds the end mark (highest set bit).</summary>
    local procedure BitInitBack(Start: Integer; Size: Integer)
    var
        LastByte: Integer;
    begin
        if Size < 1 then
            Error(CorruptErr);
        LastByte := InText[Start + Size - 1];
        if LastByte = 0 then
            Error(CorruptErr);
        BrAvail := HighBit(LastByte);
        BrContainer := LastByte mod Pow2B[BrAvail + 1]; // drop the end mark
        BrPos := Start + Size - 2;
        BrStart := Start;
        BrOver := 0;
    end;

    // HOT-INLINE : next N bits (most recently written first) ; past the stream start reads zeros, counted in BrOver
    local procedure ReadBitsBack(N: Integer) Value: BigInteger
    var
        C: Integer;
        Sh: Integer;
    begin
        if N = 0 then
            exit(0);
        while (BrAvail <= 48) and (BrPos >= BrStart) do begin
            C := InText[BrPos];
            BrContainer := BrContainer * 256 + C;
            BrPos -= 1;
            BrAvail += 8;
        end;
        if BrAvail >= N then begin
            Sh := BrAvail - N;
            Value := BrContainer div Pow2B[Sh + 1];
            BrContainer := BrContainer mod Pow2B[Sh + 1];
            BrAvail := Sh;
            exit;
        end;
        Value := BrContainer * Pow2B[N - BrAvail + 1];
        BrOver += N - BrAvail;
        BrContainer := 0;
        BrAvail := 0;
    end;

    local procedure BitsLeft(): Integer
    begin
        exit(BrAvail + (BrPos - BrStart + 1) * 8 - BrOver);
    end;

    /// <summary>N (<= 32) bits starting at bit BitPos of InText[ByteBase ..], little-endian, bytes past InLen read as 0.</summary>
    local procedure ExtractBits(ByteBase: Integer; BitPos: Integer; N: Integer): BigInteger
    var
        Acc: BigInteger;
        Mul: BigInteger;
        Idx: Integer;
        Shift: Integer;
        C: Integer;
        K: Integer;
    begin
        Idx := ByteBase + BitPos div 8;
        Shift := BitPos mod 8;
        Mul := 1;
        for K := 0 to (Shift + N - 1) div 8 do begin
            if Idx + K <= InLen then begin
                C := InText[Idx + K];
                Acc += C * Mul;
            end;
            Mul *= 256;
        end;
        exit((Acc div Pow2B[Shift + 1]) mod Pow2B[N + 1]);
    end;

    #endregion

    #region Decompress : FSE (stage 2)
    /// <summary>
    /// FSE table description (RFC 8878 4.1.1), forward bitstream at InText[Pos]. Fills NormCount[S + 1], advances Pos.
    /// </summary>
    local procedure ReadNCount(var Pos: Integer; MaxSymbol: Integer; MaxTableLog: Integer) TableLog: Integer
    var
        BitPos: Integer;
        Remaining: Integer;
        Threshold: Integer;
        NbBits: Integer;
        S: Integer;
        Max: Integer;
        V: Integer;
        Count: Integer;
        Repeat2: Integer;
        Previous0: Boolean;
    begin
        InitTables();
        for S := 1 to MaxSymbol + 1 do
            NormCount[S] := 0;
        TableLog := ExtractBits(Pos, 0, 4) + 5;
        if TableLog > MaxTableLog then
            Error(CorruptErr);
        BitPos := 4;
        Remaining := Pow2B[TableLog + 1] + 1;
        Threshold := Pow2B[TableLog + 1];
        NbBits := TableLog + 1;
        S := 0;
        while (Remaining > 1) and (S <= MaxSymbol) do begin
            if Previous0 then begin
                // zero-probability run : 2-bit repeat flags, 3 = another flag follows
                repeat
                    Repeat2 := ExtractBits(Pos, BitPos, 2);
                    BitPos += 2;
                    S += Repeat2;
                until Repeat2 <> 3;
                if S > MaxSymbol then
                    Error(CorruptErr);
            end;
            Max := 2 * Threshold - 1 - Remaining;
            V := ExtractBits(Pos, BitPos, NbBits);
            if V mod Threshold < Max then begin
                Count := V mod Threshold;
                BitPos += NbBits - 1;
            end else begin
                Count := V mod (2 * Threshold);
                if Count >= Threshold then
                    Count -= Max;
                BitPos += NbBits;
            end;
            Count -= 1; // -1 = "less than 1" probability
            if Count < 0 then
                Remaining += Count
            else
                Remaining -= Count;
            NormCount[S + 1] := Count;
            S += 1;
            Previous0 := Count = 0;
            if Remaining < 1 then
                Error(CorruptErr); // else the threshold loop below never ends
            while Remaining < Threshold do begin
                NbBits -= 1;
                Threshold := Threshold div 2;
            end;
        end;
        if Remaining <> 1 then
            Error(CorruptErr);
        Pos += (BitPos + 7) div 8;
    end;

    /// <summary>FSE decode table for Slot (1 LL, 2 OF, 3 ML, 4 Huffman weights) from NormCount (RFC 8878 4.1.1).</summary>
    local procedure BuildDTable(Slot: Integer; MaxSymbol: Integer; TableLog: Integer)
    var
        Size: Integer;
        High: Integer;
        Base: Integer;
        Step: Integer;
        Pos: Integer;
        S: Integer;
        I: Integer;
        U: Integer;
        NextState: Integer;
        NbBits: Integer;
    begin
        InitTables();
        Size := Pow2B[TableLog + 1];
        High := Size - 1;
        Base := (Slot - 1) * 512;
        // "less than 1" symbols take the last cells
        for S := 0 to MaxSymbol do
            if NormCount[S + 1] = -1 then begin
                DSymbol[Base + High + 1] := S;
                High -= 1;
                SymbolNext[S + 1] := 1;
            end else
                SymbolNext[S + 1] := NormCount[S + 1];
        // spread the others
        Step := Size div 2 + Size div 8 + 3;
        Pos := 0;
        for S := 0 to MaxSymbol do
            for I := 1 to NormCount[S + 1] do begin
                DSymbol[Base + Pos + 1] := S;
                repeat
                    Pos := (Pos + Step) mod Size;
                until Pos <= High;
            end;
        if Pos <> 0 then
            Error(CorruptErr);
        // state -> (symbol, bits to read, baseline)
        for U := 0 to Size - 1 do begin
            S := DSymbol[Base + U + 1];
            NextState := SymbolNext[S + 1];
            SymbolNext[S + 1] += 1;
            NbBits := TableLog - HighBit(NextState);
            DNbBits[Base + U + 1] := NbBits;
            DBase[Base + U + 1] := NextState * Pow2B[NbBits + 1] - Size;
        end;
        DTableLog[Slot] := TableLog;
    end;

    #endregion

    /// <summary>
    /// Parser settings behind each level (window 16 MB). Chosen 2026-09-24 on 108 files / 763 MB of a real cloud export
    /// with a byte-identical C# port of this encoder + an AL time model fitted on BC runs (ms per raw MB) :
    ///   Fast   (5-byte short hash)                         153.8 -> 155.7 MB (+1.2 %), ~7 % faster
    ///   Medium lazy 1, MinMatch 6, depth 8, skip-run insert 143.3 MB, ~176 ms/MB (old lazy MinMatch 4 : 144.7 MB, 220 ms/MB)
    ///   Heavy  lazy 1, MinMatch 6, depth 16, max insert 128 140.5 MB, ~229 ms/MB (old MinMatch 4 : 143.6 MB, 257 ms/MB)
    /// Measured and rejected : greedy Medium (150.1 MB : barely below Fast), LDM only above 1 MB (LDM matches spare the lazy
    /// parse), Heavy max insert / max lazy / nice limits, depth 24-32 (-0.5 to -0.9 % size for +7 to +13 % time).
    /// These are the ColumnData profile ; the General profile adjusts them in ApplyGeneralProfile.
    /// </summary>
    local procedure ApplyLevel(Level: Enum "TOO ZSTD Level"; Profile: Enum "TOO ZSTD Profile")
    var
        I: Integer;
    begin
        WindowLog := 24;
        SearchDepth := 16;
        LazyDepth := 1;
        MinMatch := 6; // hashed bytes = shortest chain match ; 6 beats 5 in size AND time on column exports
        LdmMinInput := 0;
        SkipRunInsert := false;
        DfShortMul := 4294967296L; // 5-byte short hash
        case Level of
            Level::Fast:
                begin
                    MaxStage := 6;
                    DoubleFast := true;
                    SpeedMode := true;
                end;
            Level::Medium:
                begin
                    MaxStage := 7;
                    DoubleFast := false;
                    SpeedMode := true;
                    SearchDepth := 8;
                    SkipRunInsert := true;
                end;
            Level::Heavy:
                begin
                    MaxStage := 7;
                    DoubleFast := false;
                    SpeedMode := false;
                end;
            else
                Error(SettingsErr);
        end;
        if SpeedMode then begin
            MaxInsertLen := 32;
            MaxLazyLen := 32;
            NiceLen := 128;
        end else begin
            MaxInsertLen := 128; // Heavy : a match > 128 indexes its last 32 positions only : same size, -1.4 % time
            MaxLazyLen := 0;
            NiceLen := 0;
        end;
        if SpeedMode then
            RepCheckCount := 1
        else
            RepCheckCount := 3;
        if Profile = Profile::General then
            ApplyGeneralProfile(Level)
        else
            if Profile <> Profile::ColumnData then
                Error(SettingsErr);
        if TuneActive then
            ApplyTuning();
        HashMul := 1;
        for I := 2 to MinMatch do
            HashMul *= 256;
    end;

    /// <summary>
    /// General profile (default) : chosen 2026-09-25 with the C# port (bench/ZstdAlPort) on general files : JSON, XML, CSV,
    /// text, source code, PDF, a binary database and enwik8, whole files and 8 / 32 / 128 / 256 KB slices, against .NET GZip
    /// (= GZipCompress). The best hashed length depends on the input size, not its type : on a small input, few candidates
    /// compete in a chain and short matches pay ; on a large one, short matches crowd the chain and hide the long ones.
    ///   <= 64 KB  : MinMatch 4 ; <= 256 KB : MinMatch 5 (crossover with 6 at ~256 KB). Lazy parse at every level (double
    ///               fast is +3 to +5 % over gz on small files), 3 repeat checks, deep search : a small input costs little
    ///               in absolute time (32 KB at ~300 ms / MB = 10 ms). No LDM : the chains reach the whole input, and LDM
    ///               matches cost 0.1-0.2 % size there. Fast : speed mode, 8 candidates ; Medium : full search, 32
    ///               candidates ; Heavy : 128 candidates, 2 lazy steps.
    ///               Size vs gz, <= 64 KB / 64-256 KB : Fast -0.7 / -3.7 %, Medium -2.0 / -5.5 %, Heavy -2.4 / -6.2 %
    ///               (ColumnData : +4.2 / +2.3 %, +0.9 / -3.4 %, +0.2 / -4.7 %).
    ///   > 256 KB  : ColumnData settings plus Fast 4-byte short hash (-3.8 % over gz vs -3.0 %, ~+6 % time), Medium 16
    ///               candidates, 3 repeat checks, no max lazy / nice limits (-12.4 % vs -10.9 %, ~+7 % time), Heavy 24
    ///               candidates, 2 lazy steps (-13.3 % vs -12.6 %, ~+10 % time).
    /// Measured and rejected : MinMatch 5 above 256 KB (-1 to -5 % worse on JSON / CSV / text), a 5-byte single-entry side
    /// table next to 6-byte chains (half the MinMatch 5 gain), double fast 4-byte short matches (+2.8 % size),
    /// compressing small inputs twice (MinMatch 4-5 and 6, keep the smaller) : -0.6 % for twice the time.
    /// </summary>
    local procedure ApplyGeneralProfile(Level: Enum "TOO ZSTD Level")
    begin
        if InLen <= 262144 then begin
            MaxStage := 6; // no LDM
            DoubleFast := false;
            RepCheckCount := 3;
            if InLen <= 65536 then
                MinMatch := 4
            else
                MinMatch := 5;
            case Level of
                Level::Fast:
                    begin
                        SearchDepth := 8; // speed mode limits of Fast kept (max insert 32, max lazy 32, nice 128)
                        SkipRunInsert := true;
                    end;
                Level::Medium:
                    begin
                        SpeedMode := false;
                        SearchDepth := 32;
                        MaxInsertLen := 128;
                        MaxLazyLen := 0;
                        NiceLen := 0;
                    end;
                Level::Heavy:
                    begin
                        SearchDepth := 128;
                        LazyDepth := 2;
                    end;
            end;
            exit;
        end;
        case Level of
            Level::Fast:
                DfShortMul := 0; // 4-byte short hash
            Level::Medium:
                begin
                    SearchDepth := 16;
                    RepCheckCount := 3;
                    MaxLazyLen := 0;
                    NiceLen := 0;
                end;
            Level::Heavy:
                begin
                    SearchDepth := 24;
                    LazyDepth := 2;
                end;
        end;
    end;

    /// <summary>SetTuning overrides (-1 = keep), consumed : one Compress call only.</summary>
    local procedure ApplyTuning()
    begin
        TuneActive := false;
        if TuneMinMatch >= 0 then
            MinMatch := TuneMinMatch;
        if TuneSearchDepth >= 0 then
            SearchDepth := TuneSearchDepth;
        if TuneLazyDepth >= 0 then
            LazyDepth := TuneLazyDepth;
        if TuneLdmMinInput >= 0 then
            LdmMinInput := TuneLdmMinInput;
        if TuneMaxInsertLen >= 0 then
            MaxInsertLen := TuneMaxInsertLen;
        if TuneMaxLazyLen >= 0 then
            MaxLazyLen := TuneMaxLazyLen;
        if TuneNiceLen >= 0 then
            NiceLen := TuneNiceLen;
        SkipRunInsert := TuneSkipRunInsert;
        if (MinMatch < 4) or (MinMatch > 6) or (SearchDepth < 1) or (LazyDepth > 2) or
           ((MaxInsertLen > 0) and (MaxInsertLen < 8)) or ((NiceLen > 0) and (NiceLen < 4))
        then
            Error(SettingsErr);
    end;

    local procedure WriteFrameHeader(SingleSegment: Boolean)
    var
        FcsFlag: Integer;
        FHD: Integer;
    begin
        PutLE(4247762216L, 4); // magic 0xFD2FB528

        // Content size always written : 1 byte (single segment only), 2 bytes (value - 256) or 4 bytes.
        // Input < 256 always fits the window (window log >= 10), so flag 0 is always single segment here.
        if InLen < 256 then
            FcsFlag := 0
        else
            if InLen < 65536 + 256 then
                FcsFlag := 1
            else
                FcsFlag := 2;
        FHD := FcsFlag * 64;
        if SingleSegment then
            FHD += 32;
        PutByte(FHD);
        if not SingleSegment then
            PutByte((WindowLog - 10) * 8); // exponent only, mantissa 0
        case FcsFlag of
            0:
                PutLE(InLen, 1);
            1:
                PutLE(InLen - 256, 2);
            2:
                PutLE(InLen, 4);
        end;
    end;

    local procedure WriteBlocks(BlockMax: Integer)
    var
        IsRun: Boolean;
        Pos: Integer;
        Size: Integer;
        LastBlock: Boolean;
    begin
        if InLen = 0 then begin
            PutBlockHeader(true, 0, 0); // empty input : one empty last raw block
            exit;
        end;
        Pos := 0;
        while Pos < InLen do begin
            Size := InLen - Pos;
            if Size > BlockMax then
                Size := BlockMax;
            LastBlock := Pos + Size >= InLen;
            // RLE block ? 3 cheap char checks first : the full 2 x Size compare runs only on likely runs
            IsRun := false;
            if Size >= 2 then
                if (InText[Pos + 2] = InText[Pos + 1]) and (InText[Pos + Size] = InText[Pos + 1]) and
                   (InText[Pos + Size div 2 + 1] = InText[Pos + 1])
                then
                    IsRun := InText.Substring(Pos + 1, Size) = Empty.PadRight(Size, InText[Pos + 1]);
            if IsRun then begin
                PutBlockHeader(LastBlock, 1, Size);
                OutTB.Append(InText.Substring(Pos + 1, 1));
            end else
                if not TryCompressedBlock(Pos, Size, LastBlock) then begin
                    PutBlockHeader(LastBlock, 0, Size);
                    OutTB.Append(InText.Substring(Pos + 1, Size));
                end;
            Pos += Size;
        end;
    end;

    local procedure PutBlockHeader(LastBlock: Boolean; BlockType: Integer; Size: Integer)
    var
        Header: Integer;
    begin
        Header := Size * 8 + BlockType * 2;
        if LastBlock then
            Header += 1;
        PutLE(Header, 3);
    end;

    #region Compress : Compressed block (stage 3)
    /// <summary>
    /// Writes a compressed block ; returns false (and writes nothing) when it would not be smaller than raw.
    /// Repeat offsets and table choices are committed only for an emitted block : the decoder never sees rejected ones.
    /// </summary>
    local procedure TryCompressedBlock(Start: Integer; Size: Integer; LastBlock: Boolean): Boolean
    var
        Slot: Integer;
        I: Integer;
    begin
        if MaxStage < 3 then
            exit(false);
        Clear(BlockTB);
        FindSequences(Start, Size);
        LitText := LitTB.ToText();
        if not TryLiteralsHuffman() then begin
            Clear(BlockTB); // drop the Huffman drafts (tree, streams) built as scratch in BlockTB
            WriteLiteralsRaw();
        end;
        WriteSequences();
        if BlockTB.Length() >= Size then
            exit(false);
        PutBlockHeader(LastBlock, 2, BlockTB.Length());
        OutTB.Append(BlockTB.ToText());

        // commit : decoder state after this block
        Rep1 := PRep1;
        Rep2 := PRep2;
        Rep3 := PRep3;
        if NbSeq > 0 then
            for Slot := 1 to 3 do begin
                ComValid[Slot] := true;
                ComRle[Slot] := SlotMode[Slot] = 1;
                ComTL[Slot] := SlotTL[Slot];
                ComMax[Slot] := SlotMax[Slot];
                for I := (Slot - 1) * 64 + 1 to Slot * 64 do
                    ComNorm[I] := SlotNorm[I];
            end;
        exit(true);
    end;

    /// <summary>
    /// Sequences of the block into SeqLL / SeqML / SeqOfv and LitTB : stage 6 hash chains + lazy, else stage 3-5 greedy.
    /// Offsets are coded on a copy of the repeat history (PRep*) committed only if the block is emitted.
    /// </summary>
    local procedure FindSequences(Start: Integer; Size: Integer)
    begin
        Clear(LitTB);
        NbSeq := 0;
        LitCount := 0;
        SeqAnchor := Start;
        PRep1 := Rep1;
        PRep2 := Rep2;
        PRep3 := Rep3;
        if (MaxStage >= 7) and (InLen > LdmMinInput) then
            ParseWithLdm(Start, Start + Size)
        else
            if DoubleFast then
                ParseDoubleFast(Start, Start + Size)
            else
                ParseLazy(Start, Start + Size);
        if Start + Size > SeqAnchor then begin
            LitTB.Append(InText.Substring(SeqAnchor + 1, Start + Size - SeqAnchor));
            LitCount += Start + Size - SeqAnchor;
        end;
    end;

    /// <summary>
    /// Stage 6 lazy parse, stage 9 inlined (one search site, no call per position ; output identical to the stage 6-7 code).
    /// Search at Q = Pos (primary) or Pos + 1 (lazy step) : chain insertion up to Q with a rolling MinMatch-byte value,
    /// candidates = the 3 repeat offsets then up to SearchDepth chain entries (19-bit hash head, chain = position mod 1M
    /// -> previous position + 1 : AL arrays cap at 1M elements, so chains reach 1M bytes back), cheap reject on the byte
    /// just past the best length, gain = 4 x length - log2(offset value). A lazy step wins when its gain beats the current
    /// one + 4 (+ 7 at depth 2), zstd ZSTD_compressBlock_lazy_generic margins. The sequence record (EmitSequence) is inline.
    /// </summary>
    local procedure ParseLazy(Pos: Integer; BlockEnd: Integer)
    var
        C: Integer;
        Q: Integer;
        Cand: Integer;
        MaxLen: Integer;
        L: Integer;
        G: Integer;
        B: Integer;
        R: Integer;
        RepNo: Integer;
        SDepth: Integer;
        BestLen: Integer;
        BestOff: Integer;
        BestGain: Integer;
        Depth: Integer;
        LL: Integer;
        OV: Integer;
        RepCode: Integer;
        RepChecks: Integer;
        Lim: Integer;
        MinCand: Integer;
        Reach: Integer;
        Last: Integer;
        QChar: Char;
        Lazy: Boolean;
        Emit: Boolean;
    begin
        Reach := WindowSize; // chain candidates : Q - Cand <= WindowSize and < 1M (Chain = position mod 1M)
        if Reach > 999999 then
            Reach := 999999;
        RepChecks := RepCheckCount; // ApplyLevel : speed mode 1 (zstd lazy : only the last offset is tried), else 3
        while Pos + 4 <= BlockEnd do begin
            if Lazy then
                Q := Pos + 1
            else
                Q := Pos;

            // chain insertion up to Q (rolling MinMatch-byte value : one char read per position). Tight loop : 1 branch per
            // position (branches cost more than math in AL). Positions past InLen - MinMatch are never inserted ; the roll
            // reads at most one char past InLen : guard char (the stale InsV it leaves is never used).
            if NextIns <= Q then begin
                Last := Q;
                if Last > InLen - MinMatch then
                    Last := InLen - MinMatch;
                if NextIns <= Last then begin
                    if InsVPos <> NextIns then begin
                        InsV := 0;
                        for L := MinMatch downto 1 do begin
                            C := InText[NextIns + L];
                            InsV := InsV * 256 + C;
                        end;
                    end;
                    // hash = InsV mod (2^19 - 1, prime) : all bytes contribute. Each AL statement costs a runtime hook
                    // (StmtHit) : the hash is computed twice and the char folded into the roll, 4 statements per position
                    repeat
                        Chain[NextIns mod 1000000 + 1] := Head[InsV mod 524287 + 1];
                        Head[InsV mod 524287 + 1] := NextIns + 1 + PosBase;
                        InsV := InsV div 256 + InText[NextIns + MinMatch + 1] * HashMul;
                        NextIns += 1;
                    until NextIns > Last;
                    InsVPos := NextIns;
                end;
                NextIns := Q + 1;
            end;

            // best match at Q (FBOff is only read when FBLen > 0 and always set with it : no reset)
            FBLen := 0;
            FBGain := 0;
            MaxLen := BlockEnd - Q;
            if MaxLen >= 4 then begin
                Lim := MaxLen; // per-byte extension limit, repeat and chain candidates
                if Lim > 16 then
                    Lim := 16;
                // repeat offsets : offset value 1..3, ~1 bit
                for RepNo := 1 to RepChecks do begin
                    case RepNo of
                        1:
                            R := PRep1;
                        2:
                            R := PRep2;
                        3:
                            R := PRep3;
                    end;
                    if (R <= Q) and (R <= WindowSize) then begin
                        // extension ladder (same as the chain candidates) : repeat matches are the long ones in column data
                        Cand := Q - R;
                        L := 0;
                        while (InText[Cand + L + 1] = InText[Q + L + 1]) and (L < Lim) do // guard char : no bound read
                            L += 1;
                        if L = 16 then begin
                            if L + 64 <= MaxLen then
                                if InText.Substring(Cand + L + 1, 64) = InText.Substring(Q + L + 1, 64) then begin
                                    L += 64;
                                    while L + 256 <= MaxLen do
                                        if InText.Substring(Cand + L + 1, 256) = InText.Substring(Q + L + 1, 256) then
                                            L += 256
                                        else
                                            break;
                                    while L + 64 <= MaxLen do
                                        if InText.Substring(Cand + L + 1, 64) = InText.Substring(Q + L + 1, 64) then
                                            L += 64
                                        else
                                            break;
                                end;
                            while (InText[Cand + L + 1] = InText[Q + L + 1]) and (L < MaxLen) do
                                L += 1;
                        end;
                        if L >= 4 then begin
                            G := L * 4 - 1;
                            if G > FBGain then begin
                                FBLen := L;
                                FBOff := R;
                                FBGain := G;
                            end;
                        end;
                    end;
                end;

                // hash chain (the head entry for Q is Q itself ; a Q past InLen - MinMatch was not inserted : its slot holds
                // an older or previous-call entry, rejected by MinCand) ; NiceLen : gzip nice_length (a repeat match that
                // long ends the search) ; speed mode good_length 8 (the lazy step only has to beat a decent match : depth / 4)
                if (FBLen < MaxLen) and not ((NiceLen > 0) and (FBLen >= NiceLen)) then begin
                    Cand := Chain[Q mod 1000000 + 1] - 1 - PosBase;
                    SDepth := SearchDepth;
                    if SpeedMode and Lazy and (BestLen >= 8) then
                        SDepth := (SearchDepth + 3) div 4;
                    // one bound test per candidate : Cand >= 0, Q - Cand <= WindowSize, Q - Cand < 1M (chain reach)
                    MinCand := Q - Reach;
                    if MinCand < 0 then
                        MinCand := 0;
                    QChar := InText[Q + FBLen + 1]; // cheap reject char, Q side : changes only with FBLen
                    while (Cand >= MinCand) and (SDepth > 0) do begin
                        if InText[Cand + FBLen + 1] = QChar then begin
                            // a candidate beats the best only if it is longer : later chain candidates are farther (same
                            // or larger log2 offset), repeat gains are 4 x L - 1. So once FBLen >= 16, its FBLen bytes are
                            // checked in one bulk compare (byte FBLen already matched the reject char), L = -1 : cannot win
                            L := 0;
                            if FBLen >= 16 then
                                if InText.Substring(Cand + 1, FBLen) = InText.Substring(Q + 1, FBLen) then
                                    L := FBLen + 1
                                else
                                    L := -1;
                            if L >= 0 then begin
                                // extension : per byte up to 16, 64-byte bulk, 256-byte bulk after a 64 hit, then per byte
                                while (InText[Cand + L + 1] = InText[Q + L + 1]) and (L < Lim) do // guard char : no bound read
                                    L += 1;
                                if L >= 16 then begin
                                    if L + 64 <= MaxLen then
                                        if InText.Substring(Cand + L + 1, 64) = InText.Substring(Q + L + 1, 64) then begin
                                            L += 64;
                                            while L + 256 <= MaxLen do
                                                if InText.Substring(Cand + L + 1, 256) = InText.Substring(Q + L + 1, 256) then
                                                    L += 256
                                                else
                                                    break;
                                            while L + 64 <= MaxLen do
                                                if InText.Substring(Cand + L + 1, 64) = InText.Substring(Q + L + 1, 64) then
                                                    L += 64
                                                else
                                                    break;
                                        end;
                                    while (InText[Cand + L + 1] = InText[Q + L + 1]) and (L < MaxLen) do
                                        L += 1;
                                end;
                            end;
                            if L >= MinMatch then begin
                                // G = 4 x L - highbit(offset + 3), highbit by table (no halving loop)
                                B := Q - Cand + 3;
                                if B <= 1024 then
                                    G := L * 4 - HBTbl[B]
                                else
                                    if B <= 1048576 then
                                        G := L * 4 - 10 - HBTbl[B div 1024]
                                    else
                                        G := L * 4 - 20 - HBTbl[B div 1048576];
                                if G > FBGain then begin
                                    FBLen := L;
                                    FBOff := Q - Cand;
                                    FBGain := G;
                                    QChar := InText[Q + FBLen + 1]; // <= BlockEnd + 1 : guard char
                                    if (L = MaxLen) or ((NiceLen > 0) and (L >= NiceLen)) then
                                        SDepth := 0;
                                end;
                            end;
                        end;
                        // no SDepth > 0 test : a stop (SDepth := 0) turns into -1 here and ends the loop, Cand is unused after
                        Cand := Chain[Cand mod 1000000 + 1] - 1 - PosBase;
                        SDepth -= 1;
                    end;
                end;
            end;

            // primary / lazy decision
            Emit := false;
            if not Lazy then begin
                if FBLen = 0 then begin
                    if SpeedMode then begin
                        Pos += 1 + (Pos - SeqAnchor) div 128; // zstd kSearchStrength 7 : longer literal run, bigger step (8 : +0.08 % size, +1.6 % time)
                        if SkipRunInsert then
                            if NextIns < Pos then
                                NextIns := Pos; // skipped positions are not indexed (step 1 : NextIns = Pos already)
                    end else
                        Pos += 1;
                end else begin
                    BestLen := FBLen;
                    BestOff := FBOff;
                    BestGain := FBGain;
                    Depth := 1;
                    // MaxLazyLen : gzip max_lazy, no lazy step after a long match
                    if (LazyDepth >= 1) and (Pos + 5 <= BlockEnd) and not ((MaxLazyLen > 0) and (BestLen >= MaxLazyLen)) then
                        Lazy := true
                    else
                        Emit := true;
                end;
            end else
                if FBGain > BestGain + 1 + 3 * Depth then begin
                    Pos += 1;
                    BestLen := FBLen;
                    BestOff := FBOff;
                    BestGain := FBGain;
                    Depth += 1;
                    if (Depth > LazyDepth) or (Pos + 5 > BlockEnd) or ((MaxLazyLen > 0) and (BestLen >= MaxLazyLen)) then
                        Emit := true;
                end else
                    Emit := true;

            if Emit then begin
                // HOT-INLINE copy of EmitSequence(Pos, BestLen, BestOff)
                LL := Pos - SeqAnchor;
                if LL > 0 then begin
                    LitTB.Append(InText.Substring(SeqAnchor + 1, LL));
                    LitCount += LL;
                end;
                OV := BestOff + 3;
                if MaxStage >= 5 then
                    if LL > 0 then begin
                        if BestOff = PRep1 then
                            OV := 1
                        else
                            if BestOff = PRep2 then
                                OV := 2
                            else
                                if BestOff = PRep3 then
                                    OV := 3;
                    end else
                        if BestOff = PRep2 then
                            OV := 1
                        else
                            if BestOff = PRep3 then
                                OV := 2
                            else
                                if BestOff = PRep1 - 1 then
                                    OV := 3;
                if OV > 3 then begin
                    PRep3 := PRep2;
                    PRep2 := PRep1;
                    PRep1 := BestOff;
                end else begin
                    RepCode := OV;
                    if LL = 0 then
                        RepCode += 1;
                    case RepCode of
                        2:
                            begin
                                PRep2 := PRep1;
                                PRep1 := BestOff;
                            end;
                        3, 4:
                            begin
                                PRep3 := PRep2;
                                PRep2 := PRep1;
                                PRep1 := BestOff;
                            end;
                    end;
                end;
                NbSeq += 1;
                SeqLL[NbSeq] := LL;
                SeqML[NbSeq] := BestLen;
                SeqOfv[NbSeq] := OV;
                SeqAnchor := Pos + BestLen;
                Pos += BestLen;
                Lazy := false;
                // gzip max_insert_length : a match > MaxInsertLen only indexes its last MaxInsertLen / 4 positions (32 : 8)
                if (MaxInsertLen > 0) and (BestLen > MaxInsertLen) and (NextIns < Pos - MaxInsertLen div 4) then
                    NextIns := Pos - MaxInsertLen div 4;
            end;
        end;
    end;

    /// <summary>
    /// Stage 9 double fast parse (zstd ZSTD_compressBlock_doubleFast, simplified) : no chains, 2 single-entry tables
    /// (DfLong : 8-byte hash, DfShort : 5-byte hash, 19 bits each), filled only where a search happens + 2 positions
    /// per match. Candidates in order : Rep1 at Pos + 1 (LL >= 1, costs ~1 bit), the 8-byte one (>= 8 equal),
    /// the 5-byte one (>= 5 equal) ; the match is extended forward (per byte to 16, 64-byte bulk, per byte) and backward
    /// into the pending literals. No match : skip 1 + (literal run) / 128 (zstd kSearchStrength 7 ; 8 : -0.03 % size, +1.2 % time).
    /// The sequence record (EmitSequence) is inline.
    /// </summary>
    local procedure ParseDoubleFast(Pos: Integer; BlockEnd: Integer)
    var
        VS: BigInteger;
        VL: BigInteger;
        HS: Integer;
        HL: Integer;
        C: Integer;
        K: Integer;
        J: Integer;
        P: Integer;
        Kind: Integer;
        CandL: Integer;
        CandS: Integer;
        Cn: Integer;
        S: Integer;
        MinL: Integer;
        MaxLen: Integer;
        L: Integer;
        ML: Integer;
        MStart: Integer;
        Off: Integer;
        NewPos: Integer;
        LL: Integer;
        OV: Integer;
        RepCode: Integer;
        VPos: Integer;
        Lim: Integer;
        Valid: Boolean;
        Same: Boolean;
    begin
        VPos := -2;
        while Pos + 8 <= BlockEnd do begin
            // 4 and 8 bytes at Pos (little-endian : VS low byte = InText[Pos + 1], VL = the next 4)
            if VPos = Pos - 1 then begin
                // rolled from Pos - 1 : one char read instead of 8
                C := InText[Pos + 8];
                VS := VS div 256 + (VL mod 256) * 16777216L;
                VL := VL div 256 + C * 16777216L;
            end else begin
                VS := 0;
                for K := 4 downto 1 do begin
                    C := InText[Pos + K];
                    VS := VS * 256 + C;
                end;
                VL := 0;
                for K := 8 downto 5 do begin
                    C := InText[Pos + K];
                    VL := VL * 256 + C;
                end;
            end;
            VPos := Pos;
            // short hash on 5 bytes (VS + the low byte of VL, zstd dfast minMatch 5) : measured 2026-09-24 on column exports
            // +1.2 % size, -7 % time (4-byte hash : a slot kept 4-byte-equal candidates that the 5-byte minimum then rejected).
            // General profile, large input : 4 bytes (DfShortMul = 0), -0.8 % size on general files. 4294967291 = prime < 2^32
            HS := ((((VS + (VL mod 256) * DfShortMul) mod 4294967291L) * 506832829) mod 4294967296L) div 8192;
            // (a mod M + b mod M) mod M = (a mod M + b) mod M : b = VS x 2654435 < 2^54, sum < 2^55
            HL := (((VL * 1640531527) mod 4294967296L + VS * 2654435) mod 4294967296L) div 8192;
            CandL := DfLong[HL + 1] - 1 - PosBase;
            CandS := DfShort[HS + 1] - 1 - PosBase;
            DfLong[HL + 1] := Pos + 1 + PosBase;
            DfShort[HS + 1] := Pos + 1 + PosBase;

            ML := 0;
            for Kind := 1 to 3 do
                if ML = 0 then begin
                    Valid := false;
                    case Kind of
                        1:
                            begin
                                S := Pos + 1;
                                Cn := S - PRep1;
                                MinL := 4;
                                Valid := Cn >= 0;
                            end;
                        2:
                            begin
                                S := Pos;
                                Cn := CandL;
                                MinL := 8;
                                if Cn >= 0 then
                                    Valid := Pos - Cn <= WindowSize;
                            end;
                        3:
                            begin
                                S := Pos;
                                Cn := CandS;
                                MinL := 5; // zstd level 3 minMatch : a 4-byte match barely pays for its sequence
                                if (Cn >= 0) and (Cn <> CandL) then
                                    Valid := Pos - Cn <= WindowSize;
                            end;
                    end;
                    if Valid then begin
                        // extension : per byte to 16, 64-byte bulk, 256-byte bulk after a 64 hit, then per byte. Measured :
                        // candidates mostly stop after a few bytes, where per-char wins ; a 64 + binary-refine Substring
                        // scheme cost 5.5 -> 8.9 s. Byte loops read one char past BlockEnd at most : guard char.
                        MaxLen := BlockEnd - S;
                        Lim := MaxLen;
                        if Lim > 16 then
                            Lim := 16;
                        L := 0;
                        while (InText[Cn + L + 1] = InText[S + L + 1]) and (L < Lim) do
                            L += 1;
                        if L = 16 then begin
                            if L + 64 <= MaxLen then
                                if InText.Substring(Cn + L + 1, 64) = InText.Substring(S + L + 1, 64) then begin
                                    L += 64;
                                    while L + 256 <= MaxLen do
                                        if InText.Substring(Cn + L + 1, 256) = InText.Substring(S + L + 1, 256) then
                                            L += 256
                                        else
                                            break;
                                    while L + 64 <= MaxLen do
                                        if InText.Substring(Cn + L + 1, 64) = InText.Substring(S + L + 1, 64) then
                                            L += 64
                                        else
                                            break;
                                end;
                            while (InText[Cn + L + 1] = InText[S + L + 1]) and (L < MaxLen) do
                                L += 1;
                        end;
                        if L >= MinL then begin
                            ML := L;
                            MStart := S;
                            Off := S - Cn;
                        end;
                    end;
                end;

            if ML = 0 then
                Pos += 1 + (Pos - SeqAnchor) div 128
            else begin
                // backward extension into the pending literals
                Same := true;
                while Same and (MStart > SeqAnchor) and (MStart - Off > 0) do
                    if InText[MStart] = InText[MStart - Off] then begin
                        MStart -= 1;
                        ML += 1;
                    end else
                        Same := false;

                // HOT-INLINE copy of EmitSequence(MStart, ML, Off)
                LL := MStart - SeqAnchor;
                if LL > 0 then begin
                    LitTB.Append(InText.Substring(SeqAnchor + 1, LL));
                    LitCount += LL;
                end;
                OV := Off + 3;
                if LL > 0 then begin
                    if Off = PRep1 then
                        OV := 1
                    else
                        if Off = PRep2 then
                            OV := 2
                        else
                            if Off = PRep3 then
                                OV := 3;
                end else
                    if Off = PRep2 then
                        OV := 1
                    else
                        if Off = PRep3 then
                            OV := 2
                        else
                            if Off = PRep1 - 1 then
                                OV := 3;
                if OV > 3 then begin
                    PRep3 := PRep2;
                    PRep2 := PRep1;
                    PRep1 := Off;
                end else begin
                    RepCode := OV;
                    if LL = 0 then
                        RepCode += 1;
                    case RepCode of
                        2:
                            begin
                                PRep2 := PRep1;
                                PRep1 := Off;
                            end;
                        3, 4:
                            begin
                                PRep3 := PRep2;
                                PRep2 := PRep1;
                                PRep1 := Off;
                            end;
                    end;
                end;
                NbSeq += 1;
                SeqLL[NbSeq] := LL;
                SeqML[NbSeq] := ML;
                SeqOfv[NbSeq] := OV;
                NewPos := MStart + ML;
                SeqAnchor := NewPos;

                // index 2 positions of the match : start + 2, end - 2
                for K := 1 to 2 do begin
                    if K = 1 then
                        P := MStart + 2
                    else
                        P := NewPos - 2;
                    if (P > Pos) and (P + 8 <= InLen) then begin
                        VS := 0;
                        for J := 4 downto 1 do begin
                            C := InText[P + J];
                            VS := VS * 256 + C;
                        end;
                        VL := 0;
                        for J := 8 downto 5 do begin
                            C := InText[P + J];
                            VL := VL * 256 + C;
                        end;
                        HS := ((((VS + (VL mod 256) * DfShortMul) mod 4294967291L) * 506832829) mod 4294967296L) div 8192;
                        HL := (((VL * 1640531527) mod 4294967296L + VS * 2654435) mod 4294967296L) div 8192;
                        DfLong[HL + 1] := P + 1 + PosBase;
                        DfShort[HS + 1] := P + 1 + PosBase;
                    end;
                end;
                VPos := -2; // VS / VL now hold P's bytes : full rebuild at the next Pos
                Pos := NewPos;
            end;
        end;
    end;

    /// <summary>
    /// Stage 7 : long-distance matches of the block (FindLdmMatches), gaps filled by the stage 6 lazy parse.
    /// Chain inserts inside a long match are skipped (NextIns jumps) : its source positions are already indexed.
    /// </summary>
    local procedure ParseWithLdm(Start: Integer; BlockEnd: Integer)
    var
        Pos: Integer;
        I: Integer;
    begin
        FindLdmMatches(Start, BlockEnd);
        Pos := Start;
        for I := 1 to LdmCount do begin
            if DoubleFast then
                ParseDoubleFast(Pos, LdmStart[I])
            else
                ParseLazy(Pos, LdmStart[I]);
            EmitSequence(LdmStart[I], LdmLen[I], LdmOff[I]);
            Pos := LdmStart[I] + LdmLen[I];
            if NextIns < Pos then
                NextIns := Pos;
        end;
        if DoubleFast then
            ParseDoubleFast(Pos, BlockEnd)
        else
            ParseLazy(Pos, BlockEnd);
    end;

    /// <summary>
    /// Long-distance matcher (zstd gear hash) : H = (H x 2 + Gear[byte]) mod 2^32 at each byte, so H depends on the last
    /// 32 bytes only (older ones are shifted out, nothing to subtract) ; 1 add + 1 lookup per byte.
    /// Content sampling : a span is used when the top 4 bits of H are 0 (1 in 16), so both copies of a repeated region
    /// sample the same spans. Table of 131 072 buckets (low 17 bits) x 4 entries (span start + 1, tag = next 11 bits).
    /// A tag hit is confirmed on the 32-byte span in bulk, extended forward in 256-byte chunks then per byte (limit BlockEnd),
    /// backward per byte (limit previous long match end / block start). Longest candidate >= 64 wins.
    /// Results in LdmStart / LdmLen / LdmOff (LdmCount), ascending, non overlapping.
    /// </summary>
    local procedure FindLdmMatches(Start: Integer; BlockEnd: Integer)
    var
        H: BigInteger;
        C: Integer;
        P: Integer;
        S: Integer;
        PEnd: Integer;
        Bucket: Integer;
        Tag: Integer;
        Slot: Integer;
        K: Integer;
        Cand: Integer;
        L: Integer;
        Back: Integer;
        LowLimit: Integer;
        BestLen: Integer;
        BestBack: Integer;
        BestCand: Integer;
        Same: Boolean;
        NeedInit: Boolean;
    begin
        LdmCount := 0;
        LowLimit := Start;
        PEnd := BlockEnd - 1; // P = last byte (0-based) of the 32-byte span, span inside the block
        if PEnd > InLen - 1 then
            PEnd := InLen - 1;
        P := Start + 31;
        NeedInit := true;
        while P <= PEnd do begin
            if NeedInit then begin
                H := 0;
                for K := P - 30 to P + 1 do begin // chars of bytes P - 31 .. P
                    C := InText[K];
                    H := (H * 2 + Gear[C + 1]) mod 4294967296L;
                end;
                NeedInit := false;
            end;

            if H < 268435456 then begin // top 4 bits 0 : 1 span in 16
                S := P - 31;
                Bucket := H mod 131072;
                Tag := (H div 131072) mod 2048;
                BestLen := 0;
                for K := 0 to 3 do begin
                    Slot := Bucket * 4 + K + 1;
                    Cand := LdmPos[Slot] - 1 - PosBase;
                    if (Cand >= 0) and (LdmTag[Slot] = Tag) then
                        if (S - Cand <= WindowSize) and (Cand < S) then
                            if InText.Substring(Cand + 1, 32) = InText.Substring(S + 1, 32) then begin
                                L := 32;
                                while S + L + 256 <= BlockEnd do
                                    if InText.Substring(Cand + L + 1, 256) = InText.Substring(S + L + 1, 256) then
                                        L += 256
                                    else
                                        break;
                                while S + L + 64 <= BlockEnd do
                                    if InText.Substring(Cand + L + 1, 64) = InText.Substring(S + L + 1, 64) then
                                        L += 64
                                    else
                                        break;
                                while (InText[Cand + L + 1] = InText[S + L + 1]) and (S + L < BlockEnd) do // guard char
                                    L += 1;
                                Back := 0;
                                Same := true;
                                while Same and (S - Back > LowLimit) and (Cand - Back > 0) do
                                    if InText[Cand - Back] = InText[S - Back] then
                                        Back += 1
                                    else
                                        Same := false;
                                if (L + Back >= 64) and (L + Back > BestLen) then begin
                                    BestLen := L + Back;
                                    BestBack := Back;
                                    BestCand := Cand;
                                end;
                            end;
                end;
                // insert the span start
                Slot := Bucket * 4 + LdmNext[Bucket + 1] + 1;
                LdmPos[Slot] := S + 1 + PosBase;
                LdmTag[Slot] := Tag;
                LdmNext[Bucket + 1] := (LdmNext[Bucket + 1] + 1) mod 4;

                if BestLen > 0 then begin
                    LdmCount += 1;
                    LdmStart[LdmCount] := S - BestBack;
                    LdmLen[LdmCount] := BestLen;
                    LdmOff[LdmCount] := S - BestCand;
                    LowLimit := S - BestBack + BestLen;
                    P := LowLimit + 31; // next span starts at the match end
                    NeedInit := true;
                end;
            end;

            // roll to the next sampled span (1 in 16) or past PEnd : 2 statements + 1 test per byte (char folded into the
            // Gear index). Rolling at P = PEnd + 1 reads InText[PEnd + 2] <= InLen + 1 : guard char (that H is never used)
            if not NeedInit then
                repeat
                    P += 1;
                    H := (H * 2 + Gear[InText[P + 1] + 1]) mod 4294967296L;
                until (H < 268435456) or (P > PEnd);
        end;
    end;

    /// <summary>
    /// Records a sequence : literals SeqAnchor .. Pos - 1 to LitTB, offset coded as the decoder reads it
    /// (repeat code 1..3, shifted when LL = 0, else offset + 3) with the decoder's history update ; Pos + ML is the new anchor.
    /// </summary>
    local procedure EmitSequence(Pos: Integer; ML: Integer; Off: Integer)
    var
        LL: Integer;
        OV: Integer;
        RepCode: Integer;
    begin
        LL := Pos - SeqAnchor;
        if LL > 0 then begin
            LitTB.Append(InText.Substring(SeqAnchor + 1, LL));
            LitCount += LL;
        end;
        OV := Off + 3;
        if MaxStage >= 5 then
            if LL > 0 then begin
                if Off = PRep1 then
                    OV := 1
                else
                    if Off = PRep2 then
                        OV := 2
                    else
                        if Off = PRep3 then
                            OV := 3;
            end else
                if Off = PRep2 then
                    OV := 1
                else
                    if Off = PRep3 then
                        OV := 2
                    else
                        if Off = PRep1 - 1 then
                            OV := 3;
        if OV > 3 then begin
            PRep3 := PRep2;
            PRep2 := PRep1;
            PRep1 := Off;
        end else begin
            RepCode := OV;
            if LL = 0 then
                RepCode += 1;
            case RepCode of
                2:
                    begin
                        PRep2 := PRep1;
                        PRep1 := Off;
                    end;
                3, 4:
                    begin
                        PRep3 := PRep2;
                        PRep2 := PRep1;
                        PRep1 := Off;
                    end;
            end;
        end;
        NbSeq += 1;
        SeqLL[NbSeq] := LL;
        SeqML[NbSeq] := ML;
        SeqOfv[NbSeq] := OV;
        SeqAnchor := Pos + ML;
    end;

    /// <summary>Raw literals section (RLE from stage 4 when all literals are one byte value) : 1, 2 or 3-byte header by size.</summary>
    local procedure WriteLiteralsRaw()
    var
        LType: Integer;
    begin
        if MaxStage >= 4 then
            if LitCount > 1 then
                if LitText = Empty.PadRight(LitCount, LitText[1]) then
                    LType := 1;
        if LitCount < 32 then
            PutBlockByte(LitCount * 8 + LType) // size format 00, 5-bit size
        else
            if LitCount < 4096 then begin
                PutBlockByte((LitCount mod 16) * 16 + 4 + LType); // size format 01, 12-bit size
                PutBlockByte(LitCount div 16);
            end else begin
                PutBlockByte((LitCount mod 16) * 16 + 12 + LType); // size format 11, 20-bit size
                PutBlockByte((LitCount div 16) mod 256);
                PutBlockByte(LitCount div 4096);
            end;
        if LType = 1 then
            BlockTB.Append(LitText.Substring(1, 1))
        else
            BlockTB.Append(LitText);
    end;
    #endregion

    #region Compress : Huffman literals (stage 4)
    /// <summary>
    /// Huffman literals section into BlockTB (empty on entry) ; false, BlockTB left empty, when it does not beat raw.
    /// Code lengths from a plain Huffman tree limited to 11 bits, canonical codes identical to the decoder table layout,
    /// tree description direct (4-bit weights) or FSE-compressed (2 states), whichever is shorter.
    /// 1 stream below 256 literals, else 4 streams of (LitCount + 3) div 4. ponytail: no treeless reuse yet (stage 5).
    /// </summary>
    local procedure TryLiteralsHuffman(): Boolean
    var
        H: BigInteger;
        TreeText: Text;
        StreamText: array[4] of Text;
        I: Integer;
        S: Integer;
        W: Integer;
        MaxSym: Integer;
        Distinct: Integer;
        Segment: Integer;
        CompSize: Integer;
        SizeFormat: Integer;
        HeaderBytes: Integer;
        NBits: Integer;
        RawHeader: Integer;
        Start: Integer;
        RankCount: array[12] of Integer;
        RankNext: array[12] of Integer;
    begin
        if (MaxStage < 4) or (LitCount < 64) then // ponytail: header + tree cost more than they save on tiny sets
            exit(false);
        Clear(LitHist);
        for I := 1 to LitCount do
            LitHist[LitText[I] + 1] += 1; // one statement (runtime hook) per literal
        for S := 0 to 255 do
            if LitHist[S + 1] > 0 then begin
                Distinct += 1;
                MaxSym := S;
            end;
        if Distinct < 2 then
            exit(false); // single byte value : RLE literals

        BuildHuffmanLengths(MaxSym);
        for S := 0 to MaxSym do
            if HufLen[S + 1] > 0 then
                HufWeight[S + 1] := HufMax + 1 - HufLen[S + 1]
            else
                HufWeight[S + 1] := 0;
        TreeText := BuildTreeDescription(MaxSym);
        if TreeText = '' then
            exit(false);

        // canonical codes : weight 1 (longest) first, symbols in order inside a weight (= decoder table order)
        for S := 0 to MaxSym do
            if HufWeight[S + 1] > 0 then
                RankCount[HufWeight[S + 1]] += 1;
        for W := 1 to HufMax do begin
            RankNext[W] := Start;
            Start += RankCount[W] * Pow2B[W];
        end;
        for S := 0 to MaxSym do begin
            W := HufWeight[S + 1];
            if W > 0 then begin
                HufCode[S + 1] := RankNext[W] div Pow2B[W];
                RankNext[W] += Pow2B[W];
            end;
        end;

        // streams
        if LitCount < 256 then begin
            StreamText[1] := EncodeHufStream(1, LitCount);
            CompSize := StrLen(TreeText) + StrLen(StreamText[1]);
            SizeFormat := 0;
        end else begin
            Segment := (LitCount + 3) div 4;
            StreamText[1] := EncodeHufStream(1, Segment);
            StreamText[2] := EncodeHufStream(Segment + 1, 2 * Segment);
            StreamText[3] := EncodeHufStream(2 * Segment + 1, 3 * Segment);
            StreamText[4] := EncodeHufStream(3 * Segment + 1, LitCount);
            CompSize := StrLen(TreeText) + 6;
            for I := 1 to 4 do
                CompSize += StrLen(StreamText[I]);
            SizeFormat := 1;
        end;
        if (LitCount > 1023) or (CompSize > 1023) then
            SizeFormat := 2;
        if (LitCount > 16383) or (CompSize > 16383) then
            SizeFormat := 3;
        if SizeFormat = 0 then
            if CompSize > 1023 then
                exit(false); // cannot happen below 256 literals ; single stream only has 10-bit sizes
        case SizeFormat of
            0, 1:
                begin
                    HeaderBytes := 3;
                    NBits := 10;
                end;
            2:
                begin
                    HeaderBytes := 4;
                    NBits := 14;
                end;
            3:
                begin
                    HeaderBytes := 5;
                    NBits := 18;
                end;
        end;
        RawHeader := 1;
        if LitCount >= 32 then
            RawHeader := 2;
        if LitCount >= 4096 then
            RawHeader := 3;
        if HeaderBytes + CompSize >= RawHeader + LitCount then
            exit(false);

        Clear(BlockTB);
        H := 2 + SizeFormat * 4 + LitCount * 16 + CompSize * Pow2B[NBits + 5];
        for I := 1 to HeaderBytes do begin
            PutBlockByte(H mod 256);
            H := H div 256;
        end;
        BlockTB.Append(TreeText);
        if SizeFormat = 0 then
            BlockTB.Append(StreamText[1])
        else begin
            for I := 1 to 3 do begin
                PutBlockByte(StrLen(StreamText[I]) mod 256);
                PutBlockByte(StrLen(StreamText[I]) div 256);
            end;
            for I := 1 to 4 do
                BlockTB.Append(StreamText[I]);
        end;
        exit(true);
    end;

    /// <summary>One backward Huffman stream for LitText[FirstIdx .. LastIdx] : written last to first, so the decoder reads FirstIdx first.</summary>
    local procedure EncodeHufStream(FirstIdx: Integer; LastIdx: Integer): Text
    var
        C: Integer;
        I: Integer;
    begin
        Clear(BlockTB);
        BwAcc := 0;
        BwCount := 0;
        for I := LastIdx downto FirstIdx do begin
            C := LitText[I];
            BwAcc += HufCode[C + 1] * Pow2B[BwCount + 1];
            BwCount += HufLen[C + 1];
            while BwCount >= 16 do begin
                BlockTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                BwAcc := BwAcc div 65536;
                BwCount -= 16;
            end;
            if BwCount >= 8 then begin
                BlockTB.Append(CharTbl[BwAcc mod 256 + 1]);
                BwAcc := BwAcc div 256;
                BwCount -= 8;
            end;
        end;
        BitCloseStream();
        exit(BlockTB.ToText());
    end;

    /// <summary>
    /// HufLen[S + 1] from LitHist : Huffman tree by repeated merge of the 2 lightest nodes (O(n^2), n <= 256),
    /// then limited to 11 bits keeping the Kraft sum exactly 2^11 (lengthen the longest codes under the limit,
    /// then shorten while there is room). HufMax = longest code.
    /// </summary>
    local procedure BuildHuffmanLengths(MaxSym: Integer)
    var
        K: BigInteger;
        Target: BigInteger;
        NLeaves: Integer;
        NNodes: Integer;
        A: Integer;
        B: Integer;
        N: Integer;
        S: Integer;
        P: Integer;
        D: Integer;
        Best: Integer;
        Len: Integer;
    begin
        Clear(HufLen);
        for S := 0 to MaxSym do
            if LitHist[S + 1] > 0 then begin
                NLeaves += 1;
                LeafSym[NLeaves] := S;
                NodeW[NLeaves] := LitHist[S + 1];
                NodeParent[NLeaves] := 0;
                NodeAlive[NLeaves] := true;
            end;
        NNodes := NLeaves;
        while NNodes < 2 * NLeaves - 1 do begin
            A := 0;
            B := 0;
            for N := 1 to NNodes do
                if NodeAlive[N] then
                    if A = 0 then
                        A := N
                    else
                        if NodeW[N] < NodeW[A] then begin
                            B := A;
                            A := N;
                        end else
                            if B = 0 then
                                B := N
                            else
                                if NodeW[N] < NodeW[B] then
                                    B := N;
            NNodes += 1;
            NodeW[NNodes] := NodeW[A] + NodeW[B];
            NodeParent[NNodes] := 0;
            NodeAlive[NNodes] := true;
            NodeParent[A] := NNodes;
            NodeParent[B] := NNodes;
            NodeAlive[A] := false;
            NodeAlive[B] := false;
        end;
        HufMax := 0;
        for N := 1 to NLeaves do begin
            D := 0;
            P := N;
            while NodeParent[P] <> 0 do begin
                P := NodeParent[P];
                D += 1;
            end;
            HufLen[LeafSym[N] + 1] := D;
            if D > HufMax then
                HufMax := D;
        end;
        if HufMax <= 11 then
            exit;

        // length limit 11 : clamp, then restore Kraft sum = 2^11 exactly
        Target := Pow2B[12];
        for S := 0 to MaxSym do
            if HufLen[S + 1] > 0 then begin
                if HufLen[S + 1] > 11 then
                    HufLen[S + 1] := 11;
                K += Pow2B[12 - HufLen[S + 1]];
            end;
        while K > Target do begin
            Best := -1;
            for S := 0 to MaxSym do begin
                Len := HufLen[S + 1];
                if (Len > 0) and (Len < 11) then
                    if Best = -1 then
                        Best := S
                    else
                        if Len > HufLen[Best + 1] then
                            Best := S;
            end;
            K -= Pow2B[11 - HufLen[Best + 1]];
            HufLen[Best + 1] += 1;
        end;
        while K < Target do begin
            Best := -1;
            for S := 0 to MaxSym do begin
                Len := HufLen[S + 1];
                if Len > 1 then
                    if K + Pow2B[12 - Len] <= Target then
                        if Best = -1 then
                            Best := S
                        else
                            if Len > HufLen[Best + 1] then
                                Best := S;
            end;
            K += Pow2B[12 - HufLen[Best + 1]];
            HufLen[Best + 1] -= 1;
        end;
        HufMax := 0;
        for S := 0 to MaxSym do
            if HufLen[S + 1] > HufMax then
                HufMax := HufLen[S + 1];
    end;

    /// <summary>Weights of symbols 0 .. MaxSym - 1 (the last one is implied) : shortest of direct / FSE ; '' when neither fits.</summary>
    local procedure BuildTreeDescription(MaxSym: Integer): Text
    var
        Direct: Text;
        Fse: Text;
        I: Integer;
        W2: Integer;
    begin
        if MaxSym <= 128 then begin
            Clear(BlockTB);
            PutBlockByte(127 + MaxSym);
            I := 1;
            while I <= MaxSym do begin
                W2 := 0;
                if I < MaxSym then
                    W2 := HufWeight[I + 1];
                PutBlockByte(HufWeight[I] * 16 + W2);
                I += 2;
            end;
            Direct := BlockTB.ToText();
        end;
        Fse := BuildWeightsFse(MaxSym);
        if Fse = '' then
            exit(Direct);
        if Direct = '' then
            exit(Fse);
        if StrLen(Fse) < StrLen(Direct) then
            exit(Fse);
        exit(Direct);
    end;

    /// <summary>
    /// FSE-compressed weights (table log 6) : NCount then 2 interleaved states, zstd FSE_compress_usingCTable order.
    /// '' when all weights are equal (the 2-state decoder never stops on 0-bit states) or the result is >= 128 bytes.
    /// </summary>
    local procedure BuildWeightsFse(N: Integer): Text
    var
        S1: Integer;
        S2: Integer;
        I: Integer;
        MaxW: Integer;
        Distinct: Integer;
    begin
        if N < 2 then
            exit('');
        Clear(HistCount);
        for I := 1 to N do begin
            HistCount[HufWeight[I] + 1] += 1;
            if HufWeight[I] > MaxW then
                MaxW := HufWeight[I];
        end;
        for I := 0 to MaxW do
            if HistCount[I + 1] > 0 then
                Distinct += 1;
        if Distinct < 2 then
            exit('');
        NormalizeCounts(MaxW, 6, N);
        BuildCTable(4, MaxW, 6);
        Clear(BlockTB);
        BwAcc := 0;
        BwCount := 0;
        WriteNCount(MaxW, 6);
        if N mod 2 = 1 then begin
            S1 := FseInitState(4, HufWeight[N]);
            S2 := FseInitState(4, HufWeight[N - 1]);
            FseEncode(4, S1, HufWeight[N - 2]);
            I := N - 3;
        end else begin
            S2 := FseInitState(4, HufWeight[N]);
            S1 := FseInitState(4, HufWeight[N - 1]);
            I := N - 2;
        end;
        while I > 0 do begin
            FseEncode(4, S2, HufWeight[I]);
            FseEncode(4, S1, HufWeight[I - 1]);
            I -= 2;
        end;
        FseFlushState(4, S2);
        FseFlushState(4, S1);
        BitCloseStream();
        if BlockTB.Length() >= 128 then
            exit('');
        exit(CharTbl[BlockTB.Length() + 1] + BlockTB.ToText());
    end;

    /// <summary>
    /// Sequences section : sequences encoded last to first (the decoder reads them first to last),
    /// per sequence FSE symbols OF, ML, LL then extra bits LL, ML, OF ; states flushed ML, OF, LL (zstd order).
    /// Tables per slot from ChooseTable (predefined, RLE, new FSE, repeat) ; an RLE slot writes no state bits.
    /// Hot loop : codes, FSE encoding and bit writes inline (HOT-INLINE copies of FseEncode / AddBits).
    /// </summary>
    local procedure WriteSequences()
    var
        V: Integer;
        N: Integer;
        Code: Integer;
        Idx: Integer;
        NB: Integer;
        Slot: Integer;
        StateLL: Integer;
        StateOF: Integer;
        StateML: Integer;
        RleLL: Boolean;
        RleOF: Boolean;
        RleML: Boolean;
    begin
        if NbSeq < 128 then
            PutBlockByte(NbSeq)
        else
            if NbSeq < 32512 then begin
                PutBlockByte(NbSeq div 256 + 128);
                PutBlockByte(NbSeq mod 256);
            end else begin
                PutBlockByte(255);
                PutBlockByte((NbSeq - 32512) mod 256);
                PutBlockByte((NbSeq - 32512) div 256);
            end;
        if NbSeq = 0 then
            exit;

        // codes (zstd ZSTD_LLcode / ZSTD_MLcode : table below 64 / 128, highbit + delta above ; OF = highbit(value)) and
        // their histograms for ChooseTable (one pass instead of 3 passes with a case per sequence)
        Clear(SeqHist);
        for N := 1 to NbSeq do begin
            V := SeqLL[N];
            if V < 64 then
                SeqLLCode[N] := LLCodeTbl[V + 1]
            else
                if V <= 1024 then
                    SeqLLCode[N] := HBTbl[V] + 19
                else
                    SeqLLCode[N] := HBTbl[V div 1024] + 29; // LL <= 128 KB
            V := SeqML[N] - 3;
            if V < 128 then
                SeqMLCode[N] := MLCodeTbl[V + 1]
            else
                if V <= 1024 then
                    SeqMLCode[N] := HBTbl[V] + 36
                else
                    SeqMLCode[N] := HBTbl[V div 1024] + 46; // ML <= 128 KB
            V := SeqOfv[N];
            if V <= 1024 then
                SeqOFCode[N] := HBTbl[V]
            else
                if V <= 1048576 then
                    SeqOFCode[N] := HBTbl[V div 1024] + 10
                else
                    SeqOFCode[N] := HBTbl[V div 1048576] + 20;
            SeqHist[SeqLLCode[N] + 1] += 1;
            SeqHist[SeqOFCode[N] + 65] += 1;
            SeqHist[SeqMLCode[N] + 129] += 1;
        end;

        // table modes and descriptions, order LL, OF, ML
        for Slot := 1 to 3 do
            ChooseTable(Slot);
        PutBlockByte(SlotMode[1] * 64 + SlotMode[2] * 16 + SlotMode[3] * 4);
        for Slot := 1 to 3 do
            case SlotMode[Slot] of
                1:
                    PutBlockByte(SlotRleSym[Slot]);
                2:
                    begin
                        LoadSlotNorm(Slot);
                        BwAcc := 0;
                        BwCount := 0;
                        WriteNCount(SlotMax[Slot], SlotTL[Slot]);
                    end;
            end;
        RleLL := SlotMode[1] = 1;
        RleOF := SlotMode[2] = 1;
        RleML := SlotMode[3] = 1;

        BwAcc := 0;
        BwCount := 0;
        N := NbSeq;
        if not RleML then
            StateML := FseInitState(3, SeqMLCode[N]);
        if not RleOF then
            StateOF := FseInitState(2, SeqOFCode[N]);
        if not RleLL then
            StateLL := FseInitState(1, SeqLLCode[N]);
        AddBits(SeqLL[N], LLBits[SeqLLCode[N] + 1]);
        AddBits(SeqML[N] - 3, MLBits[SeqMLCode[N] + 1]);
        AddBits(SeqOfv[N], SeqOFCode[N]);
        for N := NbSeq - 1 downto 1 do begin
            // FSE symbols OF (slot 2), ML (slot 3), LL (slot 1) : <= 26 bits + 7 pending
            if not RleOF then begin
                Idx := 64 + SeqOFCode[N] + 1;
                NB := (StateOF + DeltaNbBits[Idx]) div 65536;
                BwAcc += (StateOF mod Pow2B[NB + 1]) * Pow2B[BwCount + 1];
                BwCount += NB;
                StateOF := CState[512 + StateOF div Pow2B[NB + 1] + DeltaFindState[Idx] + 1];
            end;
            if not RleML then begin
                Idx := 128 + SeqMLCode[N] + 1;
                NB := (StateML + DeltaNbBits[Idx]) div 65536;
                BwAcc += (StateML mod Pow2B[NB + 1]) * Pow2B[BwCount + 1];
                BwCount += NB;
                StateML := CState[1024 + StateML div Pow2B[NB + 1] + DeltaFindState[Idx] + 1];
            end;
            if not RleLL then begin
                Idx := SeqLLCode[N] + 1;
                NB := (StateLL + DeltaNbBits[Idx]) div 65536;
                BwAcc += (StateLL mod Pow2B[NB + 1]) * Pow2B[BwCount + 1];
                BwCount += NB;
                StateLL := CState[StateLL div Pow2B[NB + 1] + DeltaFindState[Idx] + 1];
            end;
            while BwCount >= 16 do begin
                BlockTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                BwAcc := BwAcc div 65536;
                BwCount -= 16;
            end;
            if BwCount >= 8 then begin
                BlockTB.Append(CharTbl[BwAcc mod 256 + 1]);
                BwAcc := BwAcc div 256;
                BwCount -= 8;
            end;
            // extra bits LL (<= 16), ML (<= 16), OF (<= 24 with window log 24) : <= 56 bits + 7 pending < 2^63
            NB := LLBits[SeqLLCode[N] + 1];
            BwAcc += (SeqLL[N] mod Pow2B[NB + 1]) * Pow2B[BwCount + 1];
            BwCount += NB;
            NB := MLBits[SeqMLCode[N] + 1];
            BwAcc += ((SeqML[N] - 3) mod Pow2B[NB + 1]) * Pow2B[BwCount + 1];
            BwCount += NB;
            NB := SeqOFCode[N];
            BwAcc += (SeqOfv[N] - Pow2B[NB + 1]) * Pow2B[BwCount + 1]; // code = highbit(value) : value mod 2^code = value - 2^code
            BwCount += NB;
            while BwCount >= 16 do begin
                BlockTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                BwAcc := BwAcc div 65536;
                BwCount -= 16;
            end;
            if BwCount >= 8 then begin
                BlockTB.Append(CharTbl[BwAcc mod 256 + 1]);
                BwAcc := BwAcc div 256;
                BwCount -= 8;
            end;
        end;
        if not RleML then
            FseFlushState(3, StateML);
        if not RleOF then
            FseFlushState(2, StateOF);
        if not RleLL then
            FseFlushState(1, StateLL);
        BitCloseStream();
    end;

    /// <summary>
    /// Table for Slot (1 LL, 2 OF, 3 ML) from the block's code histogram. Stage < 5 : predefined.
    /// Stage 5 : RLE when one code only, else the cheapest of predefined / repeat previous / new FSE by estimated bits
    /// (sum count x (tableLog - log2 norm), log2 in 1/256 bit, + the new table description size). Builds the CTable.
    /// </summary>
    local procedure ChooseTable(Slot: Integer)
    var
        CostPre: BigInteger;
        CostRep: BigInteger;
        CostNew: BigInteger;
        Base: Integer;
        MaxLog: Integer;
        MaxUsed: Integer;
        Distinct: Integer;
        PreMax: Integer;
        PreTL: Integer;
        NewTL: Integer;
        S: Integer;
        Norm: Integer;
        L0: Integer;
        PreNorm: array[64] of Integer;
        NewNorm: array[64] of Integer;
    begin
        Base := (Slot - 1) * 64;
        // histogram of the slot's codes (SeqHist, filled by WriteSequences) ; MaxUsed = largest code used
        for S := 0 to 63 do begin
            HistCount[S + 1] := SeqHist[Base + S + 1];
            if HistCount[S + 1] > 0 then begin
                MaxUsed := S;
                Distinct += 1;
            end;
        end;

        // predefined
        SetPredefinedNorm(Slot, PreMax, PreTL);
        for S := 0 to PreMax do
            PreNorm[S + 1] := NormCount[S + 1];
        if MaxStage < 5 then begin
            SetSlot(Slot, 0, PreMax, PreTL, PreNorm, 0);
            exit;
        end;
        if Distinct = 1 then begin
            SetSlot(Slot, 1, MaxUsed, 0, PreNorm, MaxUsed);
            exit;
        end;
        CostPre := -1; // -1 = not usable
        if MaxUsed <= PreMax then begin
            CostPre := 0;
            for S := 0 to MaxUsed do
                if HistCount[S + 1] > 0 then begin
                    Norm := PreNorm[S + 1];
                    if Norm < 0 then
                        Norm := 1;
                    CostPre += HistCount[S + 1] * (PreTL * 256 - Log2Q8[Norm]);
                end;
        end;

        // repeat previous (FSE table only, all used codes must have a probability)
        CostRep := -1;
        if ComValid[Slot] and not ComRle[Slot] and (MaxUsed <= ComMax[Slot]) then begin
            CostRep := 0;
            for S := 0 to MaxUsed do
                if HistCount[S + 1] > 0 then begin
                    Norm := ComNorm[Base + S + 1];
                    if Norm < 0 then
                        Norm := 1;
                    if Norm = 0 then
                        CostRep := -1;
                    if CostRep >= 0 then
                        CostRep += HistCount[S + 1] * (ComTL[Slot] * 256 - Log2Q8[Norm]);
                end;
        end;

        // new table : zstd FSE_optimalTableLog bounds, then real description size
        case Slot of
            2:
                MaxLog := 8;
            else
                MaxLog := 9;
        end;
        NewTL := MaxLog;
        if HighBit(NbSeq - 1) - 2 < NewTL then
            NewTL := HighBit(NbSeq - 1) - 2;
        if HighBit(MaxUsed) + 2 > NewTL then
            NewTL := HighBit(MaxUsed) + 2;
        if NewTL < 5 then
            NewTL := 5;
        if NewTL > MaxLog then
            NewTL := MaxLog;
        NormalizeCounts(MaxUsed, NewTL, NbSeq);
        CostNew := 0;
        for S := 0 to MaxUsed do begin
            NewNorm[S + 1] := NormCount[S + 1];
            if HistCount[S + 1] > 0 then begin
                Norm := NormCount[S + 1];
                if Norm < 0 then
                    Norm := 1;
                CostNew += HistCount[S + 1] * (NewTL * 256 - Log2Q8[Norm]);
            end;
        end;
        L0 := BlockTB.Length();
        BwAcc := 0;
        BwCount := 0;
        WriteNCount(MaxUsed, NewTL);
        CostNew += (BlockTB.Length() - L0) * 8 * 256;
        BlockTB.Remove(L0 + 1, BlockTB.Length() - L0);

        // cheapest ; ties keep the simpler mode
        if (CostPre >= 0) and ((CostRep < 0) or (CostPre <= CostRep)) and (CostPre <= CostNew) then
            SetSlot(Slot, 0, PreMax, PreTL, PreNorm, 0)
        else
            if (CostRep >= 0) and (CostRep <= CostNew) then begin
                for S := 0 to ComMax[Slot] do
                    NewNorm[S + 1] := ComNorm[Base + S + 1];
                SetSlot(Slot, 3, ComMax[Slot], ComTL[Slot], NewNorm, 0);
            end else
                SetSlot(Slot, 2, MaxUsed, NewTL, NewNorm, 0);
    end;

    /// <summary>Records the slot's choice and builds its CTable (not for RLE : no state bits).</summary>
    local procedure SetSlot(Slot: Integer; Mode: Integer; MaxSymbol: Integer; TableLog: Integer; var Norm: array[64] of Integer; RleSymbol: Integer)
    var
        Base: Integer;
        S: Integer;
    begin
        Base := (Slot - 1) * 64;
        SlotMode[Slot] := Mode;
        SlotMax[Slot] := MaxSymbol;
        SlotTL[Slot] := TableLog;
        SlotRleSym[Slot] := RleSymbol;
        for S := 0 to 63 do
            if S <= MaxSymbol then
                SlotNorm[Base + S + 1] := Norm[S + 1]
            else
                SlotNorm[Base + S + 1] := 0;
        if Mode = 1 then
            exit;
        LoadSlotNorm(Slot);
        BuildCTable(Slot, MaxSymbol, TableLog);
    end;

    local procedure LoadSlotNorm(Slot: Integer)
    var
        S: Integer;
    begin
        for S := 0 to SlotMax[Slot] do
            NormCount[S + 1] := SlotNorm[(Slot - 1) * 64 + S + 1];
    end;

    #endregion

    #region Compress : Input / output
    local procedure PutByte(Value: Integer)
    begin
        OutTB.Append(CharTbl[Value + 1]);
    end;

    local procedure PutBlockByte(Value: Integer)
    begin
        BlockTB.Append(CharTbl[Value + 1]);
    end;

    local procedure PutLE(Value: BigInteger; Count: Integer)
    var
        I: Integer;
    begin
        for I := 1 to Count do begin
            OutTB.Append(CharTbl[Value mod 256 + 1]);
            Value := Value div 256;
        end;
    end;

    #endregion

    #region Compress : Bit writer (stage 2)
    // HOT-INLINE : forward little-endian bit accumulator, low N bits of Value (masked), whole bytes flushed to BlockTB
    local procedure AddBits(Value: BigInteger; N: Integer)
    begin
        if N = 0 then
            exit;
        BwAcc += (Value mod Pow2B[N + 1]) * Pow2B[BwCount + 1];
        BwCount += N;
        while BwCount >= 16 do begin
            BlockTB.Append(PairTbl[BwAcc mod 65536 + 1]);
            BwAcc := BwAcc div 65536;
            BwCount -= 16;
        end;
        if BwCount >= 8 then begin
            BlockTB.Append(CharTbl[BwAcc mod 256 + 1]);
            BwAcc := BwAcc div 256;
            BwCount -= 8;
        end;
    end;

    /// <summary>Backward-readable stream end : 1-bit end mark, then pad the last byte with zeros.</summary>
    local procedure BitCloseStream()
    begin
        AddBits(1, 1);
        BitFlushPartial();
    end;

    local procedure BitFlushPartial()
    begin
        if BwCount > 0 then
            BlockTB.Append(CharTbl[BwAcc + 1]);
        BwAcc := 0;
        BwCount := 0;
    end;

    #endregion

    #region Compress : FSE (stage 2)
    /// <summary>
    /// HistCount[S + 1] (Total) -> NormCount[S + 1] summing to 2^TableLog ; rare symbols get -1 ("less than 1", one cell).
    /// ponytail: simple rounding + fix-up on the largest symbols ; zstd's cost-aware normalization if stage 5 shows a ratio gap.
    /// </summary>
    local procedure NormalizeCounts(MaxSymbol: Integer; TableLog: Integer; Total: Integer)
    var
        Scale: BigInteger;
        Used: Integer;
        Diff: Integer;
        S: Integer;
        Largest: Integer;
    begin
        InitTables();
        Scale := Pow2B[TableLog + 1];
        for S := 0 to MaxSymbol do begin
            NormCount[S + 1] := 0;
            if HistCount[S + 1] > 0 then
                if HistCount[S + 1] * Scale < Total then begin
                    NormCount[S + 1] := -1;
                    Used += 1;
                end else begin
                    NormCount[S + 1] := (HistCount[S + 1] * Scale * 2 + Total) div (2 * Total); // rounded
                    if NormCount[S + 1] < 1 then
                        NormCount[S + 1] := 1;
                    Used += NormCount[S + 1];
                end;
        end;
        Diff := Scale - Used;
        while Diff <> 0 do begin
            Largest := 0;
            for S := 1 to MaxSymbol do
                if NormCount[S + 1] > NormCount[Largest + 1] then
                    Largest := S;
            if Diff > 0 then begin
                NormCount[Largest + 1] += Diff;
                Diff := 0;
            end else begin
                if NormCount[Largest + 1] <= 1 then
                    Error(PlatformErr);
                NormCount[Largest + 1] -= 1;
                Diff += 1;
            end;
        end;
    end;

    /// <summary>FSE table description (RFC 8878 4.1.1) from NormCount, forward bits to BlockTB, last byte zero-padded.</summary>
    local procedure WriteNCount(MaxSymbol: Integer; TableLog: Integer)
    var
        Remaining: Integer;
        Threshold: Integer;
        NbBits: Integer;
        S: Integer;
        Start: Integer;
        Count: Integer;
        Max: Integer;
        Previous0: Boolean;
    begin
        InitTables();
        Remaining := Pow2B[TableLog + 1] + 1;
        Threshold := Pow2B[TableLog + 1];
        NbBits := TableLog + 1;
        AddBits(TableLog - 5, 4);
        while (S <= MaxSymbol) and (Remaining > 1) do begin
            if Previous0 then begin
                Start := S;
                while (S <= MaxSymbol) and (NormCount[S + 1] = 0) do
                    S += 1;
                while Start + 3 <= S do begin
                    AddBits(3, 2);
                    Start += 3;
                end;
                AddBits(S - Start, 2);
            end;
            Count := NormCount[S + 1];
            S += 1;
            Max := 2 * Threshold - 1 - Remaining;
            if Count < 0 then
                Remaining += Count
            else
                Remaining -= Count;
            Count += 1;
            if Count >= Threshold then
                Count += Max;
            if Count < Max then
                AddBits(Count, NbBits - 1)
            else
                AddBits(Count, NbBits);
            Previous0 := Count = 1;
            if Remaining < 1 then
                Error(PlatformErr);
            while Remaining < Threshold do begin
                NbBits -= 1;
                Threshold := Threshold div 2;
            end;
        end;
        if Remaining <> 1 then
            Error(PlatformErr);
        BitFlushPartial();
    end;

    /// <summary>FSE encode table for Slot (1 LL, 2 OF, 3 ML, 4 Huffman weights) from NormCount (zstd FSE_buildCTable).</summary>
    local procedure BuildCTable(Slot: Integer; MaxSymbol: Integer; TableLog: Integer)
    var
        Size: Integer;
        High: Integer;
        Base: Integer;
        SBase: Integer;
        Step: Integer;
        Pos: Integer;
        S: Integer;
        I: Integer;
        U: Integer;
        Total: Integer;
        MaxBitsOut: Integer;
    begin
        InitTables();
        Size := Pow2B[TableLog + 1];
        High := Size - 1;
        Base := (Slot - 1) * 512;
        SBase := (Slot - 1) * 64;
        // Cumul[S + 1] = first state slot of symbol S ; "less than 1" symbols take the last cells
        Cumul[1] := 0;
        for S := 0 to MaxSymbol do
            if NormCount[S + 1] = -1 then begin
                Cumul[S + 2] := Cumul[S + 1] + 1;
                TableSymbol[High + 1] := S;
                High -= 1;
            end else
                Cumul[S + 2] := Cumul[S + 1] + NormCount[S + 1];
        Step := Size div 2 + Size div 8 + 3;
        Pos := 0;
        for S := 0 to MaxSymbol do
            for I := 1 to NormCount[S + 1] do begin
                TableSymbol[Pos + 1] := S;
                repeat
                    Pos := (Pos + Step) mod Size;
                until Pos <= High;
            end;
        // state table, sorted by symbol
        for U := 0 to Size - 1 do begin
            S := TableSymbol[U + 1];
            CState[Base + Cumul[S + 1] + 1] := Size + U;
            Cumul[S + 1] += 1;
        end;
        // symbol transforms
        for S := 0 to MaxSymbol do
            case NormCount[S + 1] of
                0:
                    DeltaNbBits[SBase + S + 1] := (TableLog + 1) * 65536 - Size;
                -1, 1:
                    begin
                        DeltaNbBits[SBase + S + 1] := TableLog * 65536 - Size;
                        DeltaFindState[SBase + S + 1] := Total - 1;
                        Total += 1;
                    end;
                else begin
                    MaxBitsOut := TableLog - HighBit(NormCount[S + 1] - 1);
                    DeltaNbBits[SBase + S + 1] := MaxBitsOut * 65536 - NormCount[S + 1] * Pow2B[MaxBitsOut + 1];
                    DeltaFindState[SBase + S + 1] := Total - NormCount[S + 1];
                    Total += NormCount[S + 1];
                end;
            end;
        CTableLog[Slot] := TableLog;
    end;

    // HOT-INLINE : first symbol goes into the initial state for free (zstd FSE_initCState2)
    local procedure FseInitState(Slot: Integer; Symbol: Integer): Integer
    var
        Idx: Integer;
        NbBitsOut: Integer;
        StateValue: Integer;
    begin
        Idx := (Slot - 1) * 64 + Symbol + 1;
        NbBitsOut := (DeltaNbBits[Idx] + 32768) div 65536;
        StateValue := NbBitsOut * 65536 - DeltaNbBits[Idx];
        exit(CState[(Slot - 1) * 512 + StateValue div Pow2B[NbBitsOut + 1] + DeltaFindState[Idx] + 1]);
    end;

    // HOT-INLINE (inline copy in WriteSequences)
    local procedure FseEncode(Slot: Integer; var State: Integer; Symbol: Integer)
    var
        Idx: Integer;
        NbBitsOut: Integer;
    begin
        Idx := (Slot - 1) * 64 + Symbol + 1;
        NbBitsOut := (State + DeltaNbBits[Idx]) div 65536;
        AddBits(State, NbBitsOut);
        State := CState[(Slot - 1) * 512 + State div Pow2B[NbBitsOut + 1] + DeltaFindState[Idx] + 1];
    end;

    local procedure FseFlushState(Slot: Integer; State: Integer)
    begin
        AddBits(State, CTableLog[Slot]);
    end;
    #endregion
}
