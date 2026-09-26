/*
    Pure-AL Brotli codec (RFC 7932), SaaS safe : no custom DotNet, no file system.
    Public API :
    - Compress(Source, Target, Level [, Profile]) : one standard brotli stream, readable by any brotli decoder (.NET
      BrotliStream, browsers, brotli CLI). Window up to 16 MB (WBITS 16..24 by input size).
      Parser : the lazy / double fast parser of codeunit "TOO ZSTD Data Compression" (same levels, same profiles, same
      matches), then a brotli back end :
        - meta-blocks of up to 1 MB, one block type per category (no block switching), NPOSTFIX = NDIRECT = 0 ;
        - literals : 64 contexts of the 2 previous bytes, context mode chosen per meta-block (LSB6 / MSB6 / UTF8 / SIGNED,
          estimate on 1 literal in 4), contexts clustered into prefix codes (greedy pair merge while it saves bits) ;
        - distances : the 16 short codes against the 4-distance ring, implicit distance 0 in command codes 0-127 ;
        - prefix codes : simple (<= 4 symbols) or complex (code length code, zero runs with code 17), lengths <= 15 ;
        - a meta-block that does not beat its raw size is stored uncompressed.
      Measured with the C# model (bench/ZstdAlPort, BrotliAl) on 54 MB of general files : -15.9 % over GZip at Heavy
      (zstd codec -13.3 %), binary database -15.6 % (zstd -9.9 %).
    - Decompress(Source, Target) : any brotli stream (RFC 7932) : block switching, context maps (RLE, inverse MTF), simple and
      complex prefix codes, NPOSTFIX / NDIRECT, uncompressed and metadata meta-blocks, static dictionary + 121 transforms.
      Windows up to 16 MB (no large-window extension). The static dictionary (122 784 bytes) is only needed for streams that
      use it (never ours) : app resource 'brotli-dictionary.bin' (resourceFolders in app.json), loaded on first use.

    Layout rules (same as the zstd codec) :
    - SingleInstance : all hot state and buffers are globals, hot code never crosses a codeunit boundary.
    - Helpers tagged // HOT-INLINE touch only globals ; hot loops carry inline copies (a call costs ~450 ns).
    - Bytes live as Latin-1 chars (char code = byte) : input read once (InText), output built in a TextBuilder written once
      (Compress) or through a sliding window (Decompress). Bit writer / reader are LSB first (brotli order), 2 bytes per
      Append through PairTbl.
    - AL has no bit operators : shifts are * / div by Pow2B, OR of two context parts goes through OrTbl.
    - AL evaluates both sides of and / or : array indexes in such conditions stay inside the declared bounds.
*/
codeunit 51160 "TOO Brotli Data Compression"
{
    Access = Public;
    SingleInstance = true;

    var
        // ---------- Shared ----------
        InText: Text;
        InLen: Integer;
        OutTB: TextBuilder;
        Empty: Text;
        CharTbl: array[256] of Text[1];
        PairTbl: array[65536] of Text[2]; // [Lo + Hi * 256 + 1] = 2 bytes, low first
        Latin1Ready: Boolean;
        TablesReady: Boolean;
        Pow2B: array[64] of BigInteger; // Pow2B[K + 1] = 2^K
        HBTbl: array[1024] of Integer; // [V] = highbit(V)
        Log2Tbl: array[65536] of Integer; // [X] = log2(X) x 256
        CtxLut: array[1024] of Integer; // [Mode * 256 + P1 + 1] : context part of the last byte (modes LSB6, MSB6, UTF8, SIGNED)
        CtxLut2: array[1024] of Integer; // [Mode * 256 + P2 + 1] : context part of the byte before
        OrTbl: array[4096] of Integer; // [A * 64 + B + 1] = A or B
        InsBase: array[53] of Integer; // [53] : shared ParseList signature
        InsExtra: array[53] of Integer;
        CopyBase: array[53] of Integer;
        CopyExtra: array[53] of Integer;
        CellIns: array[53] of Integer;
        CellCopy: array[53] of Integer;
        CellOf: array[53] of Integer; // [InsCode div 8 * 3 + CopyCode div 8 + 1] = command cell (explicit distance)
        BlkBase: array[53] of Integer;
        BlkExtra: array[53] of Integer;
        ClOrder: array[53] of Integer;
        NDBits: array[53] of Integer;
        DOffset: array[53] of Integer; // [L + 1] : first byte of the dictionary words of length L
        InsCodeTbl: array[2048] of Integer; // [V + 1] = insert length code, V < 2048
        CopyCodeTbl: array[2048] of Integer;
        // Distance ring : last = Rb[(RbIdx + 3) mod 4 + 1]
        Rb: array[4] of Integer;
        RbIdx: Integer;
        MaxBack: Integer;
        // ---------- Compress : parser (codeunit "TOO ZSTD Data Compression") ----------
        MaxStage: Integer;
        WindowLog: Integer;
        WindowSize: Integer;
        Head: array[524288] of Integer;
        Chain: array[1000000] of Integer;
        NextIns: Integer;
        PosBase: Integer;
        InsV: BigInteger;
        InsVPos: Integer;
        SeqAnchor: Integer;
        FBLen: Integer;
        FBOff: Integer;
        FBGain: Integer;
        SearchDepth: Integer;
        LazyDepth: Integer;
        DoubleFast: Boolean;
        DfLong: array[524288] of Integer;
        DfShort: array[524288] of Integer;
        SpeedMode: Boolean;
        MinMatch: Integer;
        HashMul: BigInteger;
        LdmMinInput: Integer;
        MaxInsertLen: Integer;
        MaxLazyLen: Integer;
        NiceLen: Integer;
        SkipRunInsert: Boolean;
        RepCheckCount: Integer;
        DfShortMul: BigInteger;
        LdmPos: array[524288] of Integer;
        LdmTag: array[524288] of Integer;
        LdmNext: array[131072] of Integer;
        Gear: array[256] of Integer;
        LdmCount: Integer;
        LdmStart: array[2100] of Integer;
        LdmLen: array[2100] of Integer;
        LdmOff: array[2100] of Integer;
        NbSeq: Integer;
        SeqLL: array[44000] of Integer;
        SeqML: array[44000] of Integer;
        SeqOff: array[44000] of Integer; // match offset
        Rep1: Integer;
        Rep2: Integer;
        Rep3: Integer;
        PRep1: Integer;
        PRep2: Integer;
        PRep3: Integer;
        // ---------- Compress : brotli back end ----------
        BwAcc: BigInteger;
        BwCount: Integer;
        NCmd: Integer;
        MetaStart: Integer; // 0-based first byte of the pending meta-block
        MetaLen: Integer;
        PendingLits: Integer;
        CmdIns: array[300000] of Integer;
        CmdCopy: array[300000] of Integer;
        CmdDist: array[300000] of Integer;
        CmdCode: array[300000] of Integer;
        CmdDCode: array[300000] of Integer; // distance symbol, -1 = none (implicit or end of meta-block)
        CmdDBits: array[300000] of Integer;
        CmdDExtra: array[300000] of Integer;
        DBits: Integer;
        DExtra: Integer;
        CmdHist: array[710] of Integer;
        DistHist: array[710] of Integer;
        CmdLen: array[710] of Integer;
        CmdCd: array[710] of Integer;
        DistLen: array[710] of Integer;
        DistCd: array[710] of Integer;
        ModeHist: array[65536] of Integer; // [Mode * 16384 + Ctx * 256 + Byte + 1], 1 literal in 4
        CtxHist: array[16384] of Integer; // [Ctx * 256 + Byte + 1] ; cluster rows after merging
        CMap: array[64] of Integer; // context -> tree
        NTrees: Integer;
        TreeRow: array[64] of Integer; // tree -> CtxHist row
        TreeOfRow: array[64] of Integer;
        ClCost: array[64] of BigInteger;
        ClAlive: array[64] of Boolean;
        PairDelta: array[4096] of BigInteger; // [A * 64 + B + 1], A < B
        LitLen: array[16384] of Integer; // [Tree * 256 + Byte + 1]
        LitCode: array[16384] of Integer;
        // prefix code scratch (alphabets up to 704)
        HHist: array[710] of Integer;
        HLen: array[710] of Integer;
        HCode: array[710] of Integer;
        HUsed: Integer;
        UsedSym: array[710] of Integer;
        LeafSym: array[710] of Integer;
        NodeW: array[1420] of BigInteger;
        NodeParent: array[1420] of Integer;
        NodeAlive: array[1420] of Boolean;
        BlCount: array[16] of Integer;
        NextCode: array[16] of Integer;
        ClHist: array[710] of Integer;
        ClLen: array[710] of Integer;
        ClCode: array[710] of Integer;
        RleSym: array[710] of Integer;
        RleExtra: array[710] of Integer;
        // ---------- Decompress ----------
        InPos: Integer;
        BrAcc: BigInteger;
        BrCnt: Integer;
        OutDropped: BigInteger;
        LitPend: Integer; // decoded literal waiting for its pair (-1 = none)
        P1: Integer;
        P2: Integer;
        TLen: array[1000000] of Integer; // prefix code tables : 8-bit root + sub tables, entry = (length, symbol)
        TVal: array[1000000] of Integer; // root entry of a sub table : length 100 + sub bits, value = sub table offset
        TNext: Integer;
        Lens: array[710] of Integer;
        Codes: array[710] of Integer;
        SubBits: array[256] of Integer;
        SubOff: array[256] of Integer;
        SimpleSym: array[4] of Integer;
        DClLen: array[18] of Integer;
        LitTreeOff: array[256] of Integer;
        CmdTreeOff: array[256] of Integer;
        DistTreeOff: array[256] of Integer;
        CMapL: array[16384] of Integer;
        CMapD: array[16384] of Integer;
        BlkN: array[3] of Integer; // 1 literal, 2 insert & copy, 3 distance
        BlkType: array[3] of Integer;
        BlkPrev: array[3] of Integer;
        BlkLen: array[3] of Integer;
        BlkTypeTree: array[3] of Integer;
        BlkLenTree: array[3] of Integer;
        LitModes: array[256] of Integer;
        Mtf: array[256] of Integer;
        DictText: Text;
        DictReady: Boolean;
        PrefixSuffix: array[50] of Text;
        TrPre: array[121] of Integer;
        TrType: array[121] of Integer;
        TrSuf: array[121] of Integer;
        CorruptErr: Label 'The brotli data is corrupted or not supported.', Comment = 'Les données brotli sont corrompues ou non supportées.';
        SettingsErr: Label 'Invalid brotli compression settings.', Comment = 'Paramètres de compression brotli invalides.';
        PlatformErr: Label 'The brotli codec cannot run on this platform.', Comment = 'Le codec brotli ne peut pas fonctionner sur cette plateforme.';
        DictErr: Label 'The brotli stream uses the static dictionary : add the app resource brotli-dictionary.bin.', Comment = 'Le flux brotli utilise le dictionnaire statique : ajouter la ressource brotli-dictionary.bin.';
        InsBaseTok: Label '0,1,2,3,4,5,6,8,10,14,18,26,34,50,66,98,130,194,322,578,1090,2114,6210,22594', Locked = true;
        InsExtraTok: Label '0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,12,14,24', Locked = true;
        CopyBaseTok: Label '2,3,4,5,6,7,8,9,10,12,14,18,22,30,38,54,70,102,134,198,326,582,1094,2118', Locked = true;
        CopyExtraTok: Label '0,0,0,0,0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,7,8,9,10,24', Locked = true;
        CellInsTok: Label '0,0,0,0,8,8,0,16,8,16,16', Locked = true;
        CellCopyTok: Label '0,8,0,8,0,8,16,0,16,8,16', Locked = true;
        CellOfTok: Label '2,3,6,4,5,8,7,9,10', Locked = true;
        BlkBaseTok: Label '1,5,9,13,17,25,33,41,49,65,81,97,113,145,177,209,241,305,369,497,753,1265,2289,4337,8433,16625', Locked = true;
        BlkExtraTok: Label '2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,6,6,7,8,9,10,11,12,13,24', Locked = true;
        ClOrderTok: Label '1,2,3,4,0,5,17,6,16,7,8,9,10,11,12,13,14,15', Locked = true;
        NDBitsTok: Label '0,0,0,0,10,10,11,11,10,10,10,10,10,9,9,8,7,7,8,7,7,6,6,5,5', Locked = true;
        Utf8P1Tok1: Label '0x9,4x2,0x2,4,0x18,8,12,16,12x2,20,12,16,24,28,12x2,32,12,36,12,44x10,32x2,24,40,28,12x2,48,52x3,48,52x3,48,52x5,48,52x5,48,52x5,24,12,28,12x3,56,60x3,56,60x3,56,60x5,56,60x5,56,60x5,24,12,28,12,0x2,1', Locked = true;
        Utf8P1Tok2: Label '0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3', Locked = true;
        Utf8P1Tok3: Label '2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3,2,3', Locked = true;
        Utf8P2Tok1: Label '0x33,1x15,2x10,1x7,2x26,1x6,3x26,1x4,0x97,2x32', Locked = true;
        TransformTok1: Label '49,0,49,49,0,0,0,0,0,49,12,49,49,10,0,49,0,47,0,0,49,4,0,0,49,0,3,49,10,49,49,0,6,49,13,49,49,1,49,1,0,0,49,0,1,0,10,0,49,0,7,49,0,9,48,0,0,49,0,8,49,0,5,49,0,10,49,0,11,49,3,49,49,0,13,49,0,14,49,14', Locked = true;
        TransformTok2: Label '49,49,2,49,49,0,15,49,0,16,0,10,49,49,0,12,5,0,49,0,0,1,49,15,49,49,0,18,49,0,17,49,0,19,49,0,20,49,16,49,49,17,49,47,0,49,49,4,49,49,0,22,49,11,49,49,0,23,49,0,24,49,0,25,49,7,49,49,1,26,49,0,27,49,0', Locked = true;
        TransformTok3: Label '28,0,0,12,49,0,29,49,20,49,49,18,49,49,6,49,49,0,21,49,10,1,49,8,49,49,0,31,49,0,32,47,0,3,49,5,49,49,9,49,0,10,1,49,10,8,5,0,21,49,11,0,49,10,10,49,0,30,0,0,5,35,0,49,47,0,2,49,10,17,49,0,36,49,0,33', Locked = true;
        TransformTok4: Label '5,0,0,49,10,21,49,10,5,49,0,37,0,0,30,49,0,38,0,11,0,49,0,39,0,11,49,49,0,34,49,11,8,49,10,12,0,0,21,49,0,40,0,10,12,49,0,41,49,0,42,49,11,17,49,0,43,0,10,5,49,11,10,0,0,34,49,10,33,49,0,44,49,11,5,45', Locked = true;
        TransformTok5: Label '0,49,0,0,33,49,10,30,49,11,30,49,0,46,49,11,1,49,10,34,0,10,33,0,11,30,0,11,1,49,11,33,49,11,21,49,11,12,0,11,5,49,11,34,0,11,12,0,10,30,0,11,34,0,10,34', Locked = true;
        PrefixSuffixTok1: Label ' |, | of the | of |s |.| and | in |"| to |">|~n|. |]| for | a | that |''| with | from | by |(|. The | on | as ', Locked = true;
        PrefixSuffixTok2: Label ' is |ing |~n~t|:|ed |="| at |ly |,|=''|.com/|. This | not |er |al |ful |ive |less |est |ize |~c~a|ous | the |e |', Locked = true;
        Writer: Codeunit DotNet_StreamWriter;
        Latin1: Codeunit DotNet_Encoding;
        Reader: Codeunit DotNet_StreamReader;

    /// <summary>Compresses Source into one brotli stream written to Target, with the General profile.</summary>
    procedure Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO Brotli Level")
    begin
        Compress(Source, Target, Level, Enum::"TOO Brotli Profile"::General);
    end;

    /// <summary>
    /// Compresses Source into one brotli stream written to Target. Profile : General (any file) or ColumnData
    /// (column-oriented table exports, the parser settings of the company data import / export tool).
    /// </summary>
    procedure Compress(var Source: InStream; var Target: OutStream; Level: Enum "TOO Brotli Level"; Profile: Enum "TOO Brotli Profile")
    var
        Pos: Integer;
        Size: Integer;
        WBits: Integer;
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
        if (MaxStage >= 7) and (InLen > LdmMinInput) then
            Clear(LdmNext);
        Clear(OutTB);
        NextIns := 0;
        InsVPos := -1;
        Rep1 := 1;
        Rep2 := 4;
        Rep3 := 8;
        WindowSize := 16777200; // brotli : 2^24 - 16
        // stream header : WBITS, smallest window that holds the input
        BwAcc := 0;
        BwCount := 0;
        WBits := 16;
        while (WBits < 24) and (Pow2B[WBits + 1] - 16 < InLen) do
            WBits += 1;
        if WBits = 16 then
            AddBits(0, 1)
        else
            if WBits >= 18 then begin
                AddBits(1, 1);
                AddBits(WBits - 17, 3);
            end else begin
                AddBits(1, 1);
                AddBits(0, 3);
                AddBits(0, 3);
            end;
        MaxBack := Pow2B[WBits + 1] - 16;
        ResetRing();
        NCmd := 0;
        MetaStart := 0;
        MetaLen := 0;
        PendingLits := 0;
        // parse per 128 KB block (the zstd block size of the parser), commands gathered into meta-blocks of 1 MB
        Pos := 0;
        while Pos < InLen do begin
            Size := InLen - Pos;
            if Size > 131072 then
                Size := 131072;
            FindSequences(Pos, Size);
            Rep1 := PRep1;
            Rep2 := PRep2;
            Rep3 := PRep3;
            AddBlockCommands(Pos, Size);
            Pos += Size;
            if (MetaLen >= 1048576) or (NCmd > 250000) then
                FlushMetaBlock();
        end;
        if PendingLits > 0 then begin
            // insert-only command : the meta-block ends inside its literals
            NCmd += 1;
            CmdIns[NCmd] := PendingLits;
            CmdCopy[NCmd] := 0;
            CmdDist[NCmd] := 0;
            MetaLen += PendingLits;
            PendingLits := 0;
        end;
        if MetaLen > 0 then
            FlushMetaBlock();
        AddBits(1, 1); // ISLAST
        AddBits(1, 1); // ISLASTEMPTY
        AlignWriter();
        Latin1.ISO88591();
        Writer.StreamWriter(Target, Latin1);
        Writer.Write(OutTB.ToText());
        Writer.Flush();
        // SingleInstance : free the per-call texts, keep the tables for the next call
        PosBase += InLen + 1;
        InText := '';
        Clear(OutTB);
    end;

    /// <summary>Decompresses the brotli stream Source into Target.</summary>
    procedure Decompress(var Source: InStream; var Target: OutStream)
    var
        WBits: Integer;
        N: Integer;
        MLen: Integer;
        MNib: Integer;
        I: Integer;
        Skip: Integer;
        IsLast: Boolean;
        Done: Boolean;
        Uncompressed: Boolean;
    begin
        InitTables();
        InitLatin1();
        ReadInput(Source);
        if InLen = 0 then
            Error(CorruptErr);
        Clear(Writer);
        Latin1.ISO88591();
        Writer.StreamWriter(Target, Latin1);
        InPos := 1;
        BrAcc := 0;
        BrCnt := 0;
        Clear(OutTB);
        OutDropped := 0;
        LitPend := -1;
        P1 := 0;
        P2 := 0;
        ResetRing();
        // WBITS
        if ReadBits(1) = 0 then
            WBits := 16
        else begin
            N := ReadBits(3);
            if N <> 0 then
                WBits := 17 + N
            else begin
                N := ReadBits(3);
                if N = 1 then
                    Error(CorruptErr); // large window extension
                if N <> 0 then
                    WBits := 8 + N
                else
                    WBits := 17;
            end;
        end;
        MaxBack := Pow2B[WBits + 1] - 16;
        repeat
            IsLast := ReadBits(1) = 1;
            if IsLast then
                Done := ReadBits(1) = 1; // ISLASTEMPTY
            if not Done then begin
                MNib := ReadBits(2);
                if MNib = 3 then begin
                    // metadata : reserved bit, MSKIPBYTES, skip length, skipped bytes
                    if ReadBits(1) <> 0 then
                        Error(CorruptErr);
                    N := ReadBits(2);
                    Skip := 0;
                    for I := 1 to N do
                        Skip += ReadBits(8) * Pow2B[8 * (I - 1) + 1];
                    if N > 0 then
                        Skip += 1;
                    AlignReader();
                    InPos += Skip;
                end else begin
                    MLen := 0;
                    for I := 1 to MNib + 4 do
                        MLen += ReadBits(4) * Pow2B[4 * (I - 1) + 1];
                    MLen += 1;
                    Uncompressed := false;
                    if not IsLast then
                        Uncompressed := ReadBits(1) = 1; // AL evaluates both sides of and : no ReadBits in a condition
                    if Uncompressed then
                        CopyUncompressed(MLen)
                    else
                        DecodeMetaBlock(MLen);
                end;
                Done := IsLast;
            end;
        until Done;
        FlushLiteral();
        Writer.Write(OutTB.ToText());
        Writer.Flush();
        // SingleInstance : free the per-call texts
        InText := '';
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
        // brotli transform strings (need CharTbl)
        InitTransforms();
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
        A: Integer;
        B: Integer;
        R: Integer;
        Frac: Integer;
        Code: Integer;
    begin
        if TablesReady then
            exit;
        Pow2B[1] := 1;
        for I := 2 to 63 do
            Pow2B[I] := Pow2B[I - 1] * 2;
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
        // log2(X) x 256 : integer part = highbit, 8 fraction bits by repeated squaring of the mantissa ; above 1024 from
        // the mantissa X div 2^(highbit - 9) in 512..1023
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
            Log2Tbl[I] := Code * 256 + Frac;
        end;
        for I := 1025 to 65536 do begin
            Code := HighBit(I);
            Log2Tbl[I] := (Code - 9) * 256 + Log2Tbl[I div Pow2B[Code - 9 + 1]];
        end;
        ParseList(InsBaseTok, InsBase);
        ParseList(InsExtraTok, InsExtra);
        ParseList(CopyBaseTok, CopyBase);
        ParseList(CopyExtraTok, CopyExtra);
        ParseList(CellInsTok, CellIns);
        ParseList(CellCopyTok, CellCopy);
        ParseList(CellOfTok, CellOf);
        ParseList(BlkBaseTok, BlkBase);
        ParseList(BlkExtraTok, BlkExtra);
        ParseList(ClOrderTok, ClOrder);
        ParseList(NDBitsTok, NDBits);
        DOffset[5] := 0;
        for I := 4 to 23 do
            DOffset[I + 2] := DOffset[I + 1] + I * Pow2B[NDBits[I + 1] + 1];
        // length code lookup for small values : largest code whose base <= value
        Code := 0;
        for I := 0 to 2047 do begin
            while (Code < 23) and (InsBase[Code + 2] <= I) do
                Code += 1;
            InsCodeTbl[I + 1] := Code;
        end;
        Code := 0;
        for I := 0 to 2047 do begin
            while (Code < 23) and (CopyBase[Code + 2] <= I) do
                Code += 1;
            CopyCodeTbl[I + 1] := Code;
        end;
        // context lookup (RFC 7932 7.1) : LSB6, MSB6, UTF8 (tables), SIGNED (8 ranges)
        for I := 0 to 255 do begin
            CtxLut[I + 1] := I mod 64;
            CtxLut2[I + 1] := 0;
            CtxLut[256 + I + 1] := I div 4;
            CtxLut2[256 + I + 1] := 0;
            R := SignedBucket(I);
            CtxLut[768 + I + 1] := R * 8;
            CtxLut2[768 + I + 1] := R;
        end;
        ParseRunList(Utf8P1Tok1 + ',' + Utf8P1Tok2 + ',' + Utf8P1Tok3, 512);
        ParseRunList(Utf8P2Tok1, 512 + 1024);
        // OrTbl : A or B for A, B < 64 (bit by bit)
        for A := 0 to 63 do
            for B := 0 to 63 do begin
                R := 0;
                for K := 0 to 5 do
                    if ((A div Pow2B[K + 1]) mod 2 = 1) or ((B div Pow2B[K + 1]) mod 2 = 1) then
                        R += Pow2B[K + 1];
                OrTbl[A * 64 + B + 1] := R;
            end;
        TablesReady := true;
    end;

    /// <summary>Run-length list "value" or "valuexcount" into CtxLut (Target < 1024) or CtxLut2 (Target - 1024), from index Target mod 1024.</summary>
    local procedure ParseRunList(Csv: Text; Target: Integer)
    var
        V: Text;
        Parts: List of [Text];
        Value: Integer;
        RunCount: Integer;
        I: Integer;
        Pos: Integer;
    begin
        Pos := Target mod 1024;
        foreach V in Csv.Split(',') do begin
            Parts := V.Split('x');
            Evaluate(Value, Parts.Get(1));
            RunCount := 1;
            if Parts.Count() > 1 then
                Evaluate(RunCount, Parts.Get(2));
            for I := 1 to RunCount do begin
                Pos += 1;
                if Target >= 1024 then
                    CtxLut2[Pos] := Value
                else
                    CtxLut[Pos] := Value;
            end;
        end;
        if Pos <> Target mod 1024 + 256 then
            Error(PlatformErr);
    end;

    local procedure SignedBucket(V: Integer): Integer
    begin
        if V = 0 then
            exit(0);
        if V < 16 then
            exit(1);
        if V < 64 then
            exit(2);
        if V < 128 then
            exit(3);
        if V < 192 then
            exit(4);
        if V < 240 then
            exit(5);
        if V < 255 then
            exit(6);
        exit(7);
    end;

    /// <summary>121 transforms (prefix id, type, suffix id) and the 50 prefix / suffix strings (~n = LF, ~t = TAB, ~c ~a = bytes C2 A0).</summary>
    local procedure InitTransforms()
    var
        V: Text;
        S: Text;
        Values: List of [Text];
        I: Integer;
        K: Integer;
    begin
        Values := (TransformTok1 + ',' + TransformTok2 + ',' + TransformTok3 + ',' + TransformTok4 + ',' + TransformTok5).Split(',');
        if Values.Count() <> 363 then
            Error(PlatformErr);
        for I := 1 to 121 do begin
            Evaluate(TrPre[I], Values.Get(3 * I - 2));
            Evaluate(TrType[I], Values.Get(3 * I - 1));
            Evaluate(TrSuf[I], Values.Get(3 * I));
        end;
        Values := (PrefixSuffixTok1 + '|' + PrefixSuffixTok2).Split('|');
        if Values.Count() <> 50 then
            Error(PlatformErr);
        I := 0;
        foreach V in Values do begin
            I += 1;
            S := '';
            K := 1;
            while K <= StrLen(V) do begin
                if (V[K] = '~') and (K < StrLen(V)) then begin
                    case V[K + 1] of
                        'n':
                            S += CharTbl[11];
                        't':
                            S += CharTbl[10];
                        'c':
                            S += CharTbl[195];
                        'a':
                            S += CharTbl[161];
                    end;
                    K += 2;
                end else begin
                    S += V.Substring(K, 1);
                    K += 1;
                end;
            end;
            PrefixSuffix[I] := S;
        end;
    end;

    local procedure HighBit(Value: Integer) Result: Integer
    begin
        while Value >= 2 do begin
            Value := Value div 2;
            Result += 1;
        end;
    end;

    /// <summary>log2(X) x 256 for any X >= 1 (table up to 65536, mantissa above).</summary>
    local procedure Log2Q8(X: BigInteger): Integer
    var
        HB: Integer;
        Y: BigInteger;
    begin
        if X <= 65536 then
            exit(Log2Tbl[X]);
        Y := X;
        while Y >= 2 do begin
            Y := Y div 2;
            HB += 1;
        end;
        exit((HB - 15) * 256 + Log2Tbl[X div Pow2B[HB - 15 + 1]]);
    end;

    local procedure ResetRing()
    begin
        Rb[1] := 16;
        Rb[2] := 15;
        Rb[3] := 11;
        Rb[4] := 4;
        RbIdx := 0;
    end;
    #endregion

    #region Compress : settings
    /// <summary>
    /// Parser settings behind each level and profile : identical to codeunit "TOO ZSTD Data Compression" (ApplyLevel,
    /// ApplyGeneralProfile), whose comments record the measurements. ColumnData = column-oriented table exports,
    /// General = any file, by input size (<= 64 KB MinMatch 4, <= 256 KB MinMatch 5, above MinMatch 6).
    /// </summary>
    local procedure ApplyLevel(Level: Enum "TOO Brotli Level"; Profile: Enum "TOO Brotli Profile")
    var
        I: Integer;
    begin
        WindowLog := 24;
        SearchDepth := 16;
        LazyDepth := 1;
        MinMatch := 6;
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
            MaxInsertLen := 128;
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
        HashMul := 1;
        for I := 2 to MinMatch do
            HashMul *= 256;
    end;

    local procedure ApplyGeneralProfile(Level: Enum "TOO Brotli Level")
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
    #endregion

    #region Compress : commands and meta-blocks
    /// <summary>Sequences of the block (SeqLL / SeqML / SeqOff) : parser of the zstd codec, repeat history drafted in PRep*.</summary>
    local procedure FindSequences(Start: Integer; Size: Integer)
    begin
        NbSeq := 0;
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
    end;

    /// <summary>Block sequences -> brotli commands (insert, copy, distance) ; the literals after the last match wait in PendingLits.</summary>
    local procedure AddBlockCommands(Start: Integer; Size: Integer)
    var
        I: Integer;
        P: Integer;
    begin
        P := Start;
        for I := 1 to NbSeq do begin
            NCmd += 1;
            CmdIns[NCmd] := PendingLits + SeqLL[I];
            CmdCopy[NCmd] := SeqML[I];
            CmdDist[NCmd] := SeqOff[I];
            MetaLen += CmdIns[NCmd] + SeqML[I];
            PendingLits := 0;
            P += SeqLL[I] + SeqML[I];
        end;
        PendingLits += Start + Size - P;
    end;

    local procedure FlushMetaBlock()
    begin
        WriteMetaBlock();
        MetaStart += MetaLen;
        MetaLen := 0;
        NCmd := 0;
    end;

    /// <summary>Distance symbol for D : short codes 0-15 against the ring, else 16 + 2 x (nbits - 1) + prefix bit (DBits, DExtra).</summary>
    local procedure DistCode(D: Integer): Integer
    var
        Last: Integer;
        Second: Integer;
        DD: Integer;
        NBits: Integer;
    begin
        DBits := 0;
        DExtra := 0;
        Last := Rb[(RbIdx + 3) mod 4 + 1];
        Second := Rb[(RbIdx + 2) mod 4 + 1];
        if D = Last then
            exit(0);
        if D = Second then
            exit(1);
        if D = Rb[(RbIdx + 1) mod 4 + 1] then
            exit(2);
        if D = Rb[RbIdx + 1] then
            exit(3);
        case D - Last of
            -1:
                exit(4);
            1:
                exit(5);
            -2:
                exit(6);
            2:
                exit(7);
            -3:
                exit(8);
            3:
                exit(9);
        end;
        case D - Second of
            -1:
                exit(10);
            1:
                exit(11);
            -2:
                exit(12);
            2:
                exit(13);
            -3:
                exit(14);
            3:
                exit(15);
        end;
        DD := D + 3; // NPOSTFIX = NDIRECT = 0
        NBits := HighBit(DD) - 1;
        DBits := NBits;
        DExtra := DD mod Pow2B[NBits + 1];
        exit(16 + 2 * (NBits - 1) + (DD div Pow2B[NBits + 1]) mod 2);
    end;

    local procedure InsCode(V: Integer) Code: Integer
    begin
        if V < 2048 then
            exit(InsCodeTbl[V + 1]);
        Code := 23;
        while InsBase[Code + 1] > V do
            Code -= 1;
    end;

    local procedure CopyCode(V: Integer) Code: Integer
    begin
        if V < 2048 then
            exit(CopyCodeTbl[V + 1]);
        Code := 23;
        while CopyBase[Code + 1] > V do
            Code -= 1;
    end;

    /// <summary>
    /// One meta-block : commands MetaStart .. MetaStart + MetaLen - 1 (NCmd). Command / distance symbols (ring simulated),
    /// literal context mode + clustering, prefix codes, header, commands. Not smaller than raw : stored uncompressed.
    /// </summary>
    local procedure WriteMetaBlock()
    var
        MarkAcc: BigInteger;
        Bits: BigInteger;
        MarkLen: Integer;
        MarkCnt: Integer;
        SaveRb: array[4] of Integer;
        SaveIdx: Integer;
        K: Integer;
        I: Integer;
        Q: Integer;
        QEnd: Integer;
        P: Integer;
        Ins: Integer;
        IC: Integer;
        CC: Integer;
        DC: Integer;
        Cell: Integer;
        Mode: Integer;
        LutOff: Integer;
        T: Integer;
        C: Integer;
        B: Integer;
        Idx: Integer;
        Nib: Integer;
    begin
        MarkLen := OutTB.Length();
        MarkAcc := BwAcc;
        MarkCnt := BwCount;
        for I := 1 to 4 do
            SaveRb[I] := Rb[I];
        SaveIdx := RbIdx;

        // command symbols and distance codes (the ring is updated as the decoder will)
        Clear(CmdHist);
        Clear(DistHist);
        for K := 1 to NCmd do begin
            if CmdIns[K] < 2048 then
                IC := InsCodeTbl[CmdIns[K] + 1]
            else
                IC := InsCode(CmdIns[K]);
            if CmdCopy[K] < 2048 then
                CC := CopyCodeTbl[CmdCopy[K] + 1] // copy 0 (insert-only tail) : code 0
            else
                CC := CopyCode(CmdCopy[K]);
            DC := -1; // -1 : no distance (insert-only tail : the meta-block ends in its literals)
            if CmdCopy[K] > 0 then begin
                DC := DistCode(CmdDist[K]);
                CmdDBits[K] := DBits;
                CmdDExtra[K] := DExtra;
                if DC <> 0 then begin
                    Rb[RbIdx + 1] := CmdDist[K];
                    RbIdx := (RbIdx + 1) mod 4;
                end;
            end;
            if (DC <= 0) and (IC < 8) and (CC < 16) then begin
                Cell := CC div 8; // implicit distance 0 (or none)
                DC := -1;
            end else
                Cell := CellOf[(IC div 8) * 3 + CC div 8 + 1];
            CmdCode[K] := Cell * 64 + (IC mod 8) * 8 + CC mod 8;
            CmdDCode[K] := DC;
            CmdHist[CmdCode[K] + 1] += 1;
            if DC >= 0 then
                DistHist[DC + 1] += 1;
        end;

        // literal contexts : mode, histograms of the chosen mode, clustering
        Mode := ChooseMode();
        LutOff := Mode * 256;
        Clear(CtxHist);
        P := MetaStart;
        for K := 1 to NCmd do begin
            Q := P;
            QEnd := P + CmdIns[K] - 1;
            while (Q <= QEnd) and (Q < 2) do begin
                C := LitContext(Q, LutOff);
                CtxHist[C * 256 + InText[Q + 1] + 1] += 1;
                Q += 1;
            end;
            for I := Q to QEnd do
                CtxHist[OrTbl[CtxLut[LutOff + InText[I] + 1] * 64 + CtxLut2[LutOff + InText[I - 1] + 1] + 1] * 256 + InText[I + 1] + 1] += 1;
            P += CmdIns[K] + CmdCopy[K];
        end;
        ClusterContexts();

        // header : ISLAST 0, MNIBBLES, MLEN - 1, ISUNCOMPRESSED 0, NBLTYPES L / I / D = 1, NPOSTFIX 0, NDIRECT 0, mode
        AddBits(0, 1);
        Nib := MetaNibbles(MetaLen);
        AddBits(Nib - 4, 2);
        AddBits(MetaLen - 1, Nib * 4);
        AddBits(0, 1);
        AddBits(0, 1);
        AddBits(0, 1);
        AddBits(0, 1);
        AddBits(0, 2);
        AddBits(0, 4);
        AddBits(Mode, 2);
        WriteVarLen(NTrees - 1);
        if NTrees > 1 then
            WriteContextMap();
        WriteVarLen(0); // NTREESD = 1
        // prefix codes : literal trees, command, distance
        for T := 0 to NTrees - 1 do begin
            for B := 0 to 255 do
                HHist[B + 1] := CtxHist[TreeRow[T + 1] * 256 + B + 1];
            PrepareCode(256);
            for B := 0 to 255 do begin
                LitLen[T * 256 + B + 1] := HLen[B + 1];
                LitCode[T * 256 + B + 1] := HCode[B + 1];
            end;
            WritePrefixCode(256);
        end;
        for I := 1 to 704 do
            HHist[I] := CmdHist[I];
        PrepareCode(704);
        for I := 1 to 704 do begin
            CmdLen[I] := HLen[I];
            CmdCd[I] := HCode[I];
        end;
        WritePrefixCode(704);
        for I := 1 to 64 do
            HHist[I] := DistHist[I];
        PrepareCode(64);
        for I := 1 to 64 do begin
            DistLen[I] := HLen[I];
            DistCd[I] := HCode[I];
        end;
        WritePrefixCode(64);

        // commands : symbol, insert extra, copy extra, literals, distance
        P := MetaStart;
        for K := 1 to NCmd do begin
            // HOT-INLINE copies of AddBits : symbol + insert extra (<= 15 + 24 bits), flush, copy extra (<= 24), flush
            C := CmdCode[K];
            IC := CellIns[C div 64 + 1] + (C div 8) mod 8;
            CC := CellCopy[C div 64 + 1] + C mod 8;
            BwAcc += CmdCd[C + 1] * Pow2B[BwCount + 1];
            BwCount += CmdLen[C + 1];
            BwAcc += (CmdIns[K] - InsBase[IC + 1]) * Pow2B[BwCount + 1];
            BwCount += InsExtra[IC + 1];
            while BwCount >= 16 do begin
                OutTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                BwAcc := BwAcc div 65536;
                BwCount -= 16;
            end;
            if CmdCopy[K] >= 2 then begin
                BwAcc += (CmdCopy[K] - CopyBase[CC + 1]) * Pow2B[BwCount + 1];
                BwCount += CopyExtra[CC + 1];
                while BwCount >= 16 do begin
                    OutTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                    BwAcc := BwAcc div 65536;
                    BwCount -= 16;
                end;
            end;
            Q := P;
            QEnd := P + CmdIns[K] - 1;
            while (Q <= QEnd) and (Q < 2) do begin
                Idx := CMap[LitContext(Q, LutOff) + 1] * 256 + InText[Q + 1] + 1;
                AddBits(LitCode[Idx], LitLen[Idx]);
                Q += 1;
            end;
            for I := Q to QEnd do begin
                // HOT-INLINE copy of AddBits(LitCode[Idx], LitLen[Idx]) : a code <= 15 bits + <= 15 pending, one flush at most
                Idx := CMap[OrTbl[CtxLut[LutOff + InText[I] + 1] * 64 + CtxLut2[LutOff + InText[I - 1] + 1] + 1] + 1] * 256 + InText[I + 1] + 1;
                BwAcc += LitCode[Idx] * Pow2B[BwCount + 1];
                BwCount += LitLen[Idx];
                if BwCount >= 16 then begin
                    OutTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                    BwAcc := BwAcc div 65536;
                    BwCount -= 16;
                end;
            end;
            if CmdDCode[K] >= 0 then begin
                // HOT-INLINE copy of AddBits : distance symbol + extra (<= 15 + 24 bits)
                BwAcc += DistCd[CmdDCode[K] + 1] * Pow2B[BwCount + 1];
                BwCount += DistLen[CmdDCode[K] + 1];
                BwAcc += CmdDExtra[K] * Pow2B[BwCount + 1];
                BwCount += CmdDBits[K];
                while BwCount >= 16 do begin
                    OutTB.Append(PairTbl[BwAcc mod 65536 + 1]);
                    BwAcc := BwAcc div 65536;
                    BwCount -= 16;
                end;
            end;
            P += CmdIns[K] + CmdCopy[K];
        end;

        // not smaller than raw (+ 4 bytes) : uncompressed meta-block instead, ring restored (the decoder never sees it)
        Bits := (OutTB.Length() - MarkLen) * 8L + BwCount - MarkCnt;
        if Bits < MetaLen * 8L + 32 then
            exit;
        if OutTB.Length() > MarkLen then
            OutTB.Remove(MarkLen + 1, OutTB.Length() - MarkLen);
        BwAcc := MarkAcc;
        BwCount := MarkCnt;
        for I := 1 to 4 do
            Rb[I] := SaveRb[I];
        RbIdx := SaveIdx;
        AddBits(0, 1);
        Nib := MetaNibbles(MetaLen);
        AddBits(Nib - 4, 2);
        AddBits(MetaLen - 1, Nib * 4);
        AddBits(1, 1); // ISUNCOMPRESSED
        AlignWriter();
        OutTB.Append(InText.Substring(MetaStart + 1, MetaLen));
    end;

    local procedure MetaNibbles(Len: Integer): Integer
    begin
        if Len - 1 < 65536 then
            exit(4);
        if Len - 1 < 1048576 then
            exit(5);
        exit(6);
    end;

    /// <summary>Context of the literal at 0-based position Q < 2 (missing previous bytes are 0).</summary>
    local procedure LitContext(Q: Integer; LutOff: Integer): Integer
    var
        C1: Integer;
        C2: Integer;
    begin
        if Q >= 1 then
            C1 := InText[Q];
        if Q >= 2 then
            C2 := InText[Q - 1];
        exit(OrTbl[CtxLut[LutOff + C1 + 1] * 64 + CtxLut2[LutOff + C2 + 1] + 1]);
    end;

    /// <summary>
    /// Literal context mode of the meta-block : histograms of 1 literal in 4 under the 4 modes, cost = per-context entropy +
    /// ~(30 + 4 x used symbols) bits per used context ; the cheapest mode wins.
    /// </summary>
    local procedure ChooseMode(): Integer
    var
        Bits: BigInteger;
        BestBits: BigInteger;
        Ent: BigInteger;
        N: BigInteger;
        K: Integer;
        Q: Integer;
        QEnd: Integer;
        P: Integer;
        M: Integer;
        Ctx: Integer;
        S: Integer;
        C: BigInteger;
        Used: Integer;
        Best: Integer;
        Byte0: Integer;
        C1: Integer;
        C2: Integer;
    begin
        Clear(ModeHist);
        P := MetaStart;
        for K := 1 to NCmd do begin
            Q := P;
            QEnd := P + CmdIns[K] - 1;
            while Q <= QEnd do begin
                Byte0 := InText[Q + 1];
                if Q >= 2 then begin
                    C1 := InText[Q];
                    C2 := InText[Q - 1];
                end else begin
                    C1 := 0;
                    C2 := 0;
                    if Q = 1 then
                        C1 := InText[1];
                end;
                ModeHist[OrTbl[CtxLut[C1 + 1] * 64 + CtxLut2[C2 + 1] + 1] * 256 + Byte0 + 1] += 1;
                ModeHist[16384 + OrTbl[CtxLut[256 + C1 + 1] * 64 + CtxLut2[256 + C2 + 1] + 1] * 256 + Byte0 + 1] += 1;
                ModeHist[32768 + OrTbl[CtxLut[512 + C1 + 1] * 64 + CtxLut2[512 + C2 + 1] + 1] * 256 + Byte0 + 1] += 1;
                ModeHist[49152 + OrTbl[CtxLut[768 + C1 + 1] * 64 + CtxLut2[768 + C2 + 1] + 1] * 256 + Byte0 + 1] += 1;
                Q += 4;
            end;
            P += CmdIns[K] + CmdCopy[K];
        end;
        Best := 0;
        BestBits := -1;
        for M := 0 to 3 do begin
            Bits := 0;
            for Ctx := 0 to 63 do begin
                N := 0;
                Used := 0;
                Ent := 0;
                for S := 0 to 255 do begin
                    C := ModeHist[M * 16384 + Ctx * 256 + S + 1];
                    if C > 0 then begin
                        N += C;
                        Used += 1;
                        if C <= 65536 then
                            Ent += C * Log2Tbl[C]
                        else
                            Ent += C * Log2Q8(C);
                    end;
                end;
                if N > 0 then
                    Bits += N * Log2Q8(N) - Ent + (30 + 4 * Used) * 256;
            end;
            if (BestBits < 0) or (Bits < BestBits) then begin
                BestBits := Bits;
                Best := M;
            end;
        end;
        exit(Best);
    end;

    /// <summary>Q8 cost of a 256-symbol histogram row (entropy + ~16 + 4.5 bits per used symbol for its prefix code).</summary>
    local procedure RowCost(Row: Integer): BigInteger
    var
        N: BigInteger;
        Ent: BigInteger;
        S: Integer;
        C: BigInteger;
        Used: Integer;
    begin
        for S := 1 to 256 do begin
            C := CtxHist[Row * 256 + S];
            if C > 0 then begin
                N += C;
                Used += 1;
                if C <= 65536 then
                    Ent += C * Log2Tbl[C]
                else
                    Ent += C * Log2Q8(C);
            end;
        end;
        if N = 0 then
            exit(0);
        exit(N * Log2Q8(N) - Ent + 4096 + 1152 * Used);
    end;

    /// <summary>Q8 cost of rows A + B merged.</summary>
    local procedure MergedCost(A: Integer; B: Integer): BigInteger
    var
        N: BigInteger;
        Ent: BigInteger;
        S: Integer;
        C: BigInteger;
        Used: Integer;
        OffA: Integer;
        OffB: Integer;
    begin
        OffA := A * 256;
        OffB := B * 256;
        for S := 1 to 256 do begin
            C := CtxHist[OffA + S] + CtxHist[OffB + S];
            if C > 0 then begin
                N += C;
                Used += 1;
                if C <= 65536 then
                    Ent += C * Log2Tbl[C]
                else
                    Ent += C * Log2Q8(C);
            end;
        end;
        if N = 0 then
            exit(0);
        exit(N * Log2Q8(N) - Ent + 4096 + 1152 * Used);
    end;

    /// <summary>
    /// 64 context histograms -> NTrees prefix codes : greedy merge of the pair that saves the most bits (pair deltas kept,
    /// recomputed only for the merged cluster) until no merge saves bits. CMap[context] = tree, TreeRow[tree] = CtxHist row.
    /// </summary>
    local procedure ClusterContexts()
    var
        Best: BigInteger;
        A: Integer;
        B: Integer;
        BA: Integer;
        BB: Integer;
        O: Integer;
        S: Integer;
        Ctx: Integer;
        Alive: Integer;
    begin
        for A := 0 to 63 do begin
            ClCost[A + 1] := RowCost(A);
            ClAlive[A + 1] := false;
            for S := 1 to 256 do
                if CtxHist[A * 256 + S] > 0 then
                    ClAlive[A + 1] := true;
            CMap[A + 1] := A;
            if ClAlive[A + 1] then
                Alive += 1;
        end;
        if Alive = 0 then
            ClAlive[1] := true; // no literal : one empty tree
        for A := 0 to 62 do
            if ClAlive[A + 1] then
                for B := A + 1 to 63 do
                    if ClAlive[B + 1] then
                        PairDelta[A * 64 + B + 1] := MergedCost(A, B) - ClCost[A + 1] - ClCost[B + 1];
        repeat
            Best := 0;
            BA := -1;
            for A := 0 to 62 do
                if ClAlive[A + 1] then
                    for B := A + 1 to 63 do
                        if ClAlive[B + 1] then
                            if PairDelta[A * 64 + B + 1] < Best then begin
                                Best := PairDelta[A * 64 + B + 1];
                                BA := A;
                                BB := B;
                            end;
            if BA >= 0 then begin
                for S := 1 to 256 do
                    CtxHist[BA * 256 + S] += CtxHist[BB * 256 + S];
                ClCost[BA + 1] := RowCost(BA);
                ClAlive[BB + 1] := false;
                for Ctx := 1 to 64 do
                    if CMap[Ctx] = BB then
                        CMap[Ctx] := BA;
                for O := 0 to 63 do
                    if ClAlive[O + 1] and (O <> BA) then
                        if O < BA then
                            PairDelta[O * 64 + BA + 1] := MergedCost(O, BA) - ClCost[O + 1] - ClCost[BA + 1]
                        else
                            PairDelta[BA * 64 + O + 1] := MergedCost(BA, O) - ClCost[BA + 1] - ClCost[O + 1];
            end;
        until BA < 0;
        NTrees := 0;
        for A := 0 to 63 do begin
            TreeOfRow[A + 1] := 0; // contexts without literals (never merged) : tree 0
            if ClAlive[A + 1] then begin
                TreeRow[NTrees + 1] := A;
                TreeOfRow[A + 1] := NTrees;
                NTrees += 1;
            end;
        end;
        for Ctx := 1 to 64 do
            CMap[Ctx] := TreeOfRow[CMap[Ctx] + 1];
    end;

    /// <summary>Context map : RLEMAX 0, one prefix code over the tree numbers, 64 symbols, no inverse MTF.</summary>
    local procedure WriteContextMap()
    var
        Ctx: Integer;
    begin
        AddBits(0, 1);
        for Ctx := 1 to NTrees do
            HHist[Ctx] := 0;
        for Ctx := 1 to 64 do
            HHist[CMap[Ctx] + 1] += 1;
        PrepareCode(NTrees);
        WritePrefixCode(NTrees);
        for Ctx := 1 to 64 do
            AddBits(HCode[CMap[Ctx] + 1], HLen[CMap[Ctx] + 1]);
        AddBits(0, 1); // IMTF
    end;

    local procedure WriteVarLen(V: Integer)
    var
        N: Integer;
    begin
        if V = 0 then begin
            AddBits(0, 1);
            exit;
        end;
        AddBits(1, 1);
        N := HighBit(V);
        AddBits(N, 3);
        if N > 0 then
            AddBits(V - Pow2B[N + 1], N);
    end;
    #endregion

    #region Compress : prefix codes
    /// <summary>
    /// HHist (AlphaSize symbols) -> HLen / HCode as they will be written : <= 4 used symbols : simple code (1 : 0 bits,
    /// 2 : 1 1, 3 : 1 2 2, 4 : 2 2 2 2 or 1 2 3 3, most frequent first) ; else Huffman lengths <= 15. Codes canonical, bit
    /// reversed (the stream is LSB first). UsedSym / HUsed : the used symbols (for WritePrefixCode).
    /// </summary>
    local procedure PrepareCode(AlphaSize: Integer)
    var
        S: Integer;
        I: Integer;
        J: Integer;
        V: Integer;
        CostA: BigInteger;
        CostB: BigInteger;
    begin
        HUsed := 0;
        for S := 0 to AlphaSize - 1 do begin
            HLen[S + 1] := 0;
            HCode[S + 1] := 0;
            if HHist[S + 1] > 0 then begin
                HUsed += 1;
                UsedSym[HUsed] := S;
            end;
        end;
        if HUsed > 4 then begin
            BuildLengths(HHist, HLen, AlphaSize, 15);
            CanonCodes(HLen, HCode, AlphaSize);
            exit;
        end;
        // most frequent first (ties : lower symbol), insertion sort of <= 4
        for I := 2 to HUsed do begin
            V := UsedSym[I];
            J := I - 1;
            while J >= 1 do begin
                if (HHist[UsedSym[J] + 1] > HHist[V + 1]) or ((HHist[UsedSym[J] + 1] = HHist[V + 1]) and (UsedSym[J] < V)) then
                    break;
                UsedSym[J + 1] := UsedSym[J];
                J -= 1;
            end;
            UsedSym[J + 1] := V;
        end;
        case HUsed of
            2:
                begin
                    HLen[UsedSym[1] + 1] := 1;
                    HLen[UsedSym[2] + 1] := 1;
                end;
            3:
                begin
                    HLen[UsedSym[1] + 1] := 1;
                    HLen[UsedSym[2] + 1] := 2;
                    HLen[UsedSym[3] + 1] := 2;
                end;
            4:
                begin
                    CostA := 2 * (HHist[UsedSym[1] + 1] + HHist[UsedSym[2] + 1] + HHist[UsedSym[3] + 1] + HHist[UsedSym[4] + 1]);
                    CostB := HHist[UsedSym[1] + 1] + 2 * HHist[UsedSym[2] + 1] + 3 * (HHist[UsedSym[3] + 1] + HHist[UsedSym[4] + 1]);
                    if CostB < CostA then begin
                        HLen[UsedSym[1] + 1] := 1;
                        HLen[UsedSym[2] + 1] := 2;
                        HLen[UsedSym[3] + 1] := 3;
                        HLen[UsedSym[4] + 1] := 3;
                    end else
                        for I := 1 to 4 do
                            HLen[UsedSym[I] + 1] := 2;
                end;
        end;
        if HUsed >= 2 then
            CanonCodes(HLen, HCode, AlphaSize);
    end;

    /// <summary>
    /// Huffman code lengths of Hist (AlphaSize symbols) into Len : tree by repeated merge of the 2 lightest nodes (O(n^2)),
    /// then limited to MaxLen keeping the Kraft sum exact (lengthen the longest codes under the limit, then shorten while
    /// there is room) ; the zstd codec's BuildHuffmanLengths with a MaxLen parameter.
    /// </summary>
    local procedure BuildLengths(var Hist: array[710] of Integer; var Len: array[710] of Integer; AlphaSize: Integer; MaxLen: Integer)
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
        L: Integer;
        MaxD: Integer;
    begin
        for S := 0 to AlphaSize - 1 do begin
            Len[S + 1] := 0;
            if Hist[S + 1] > 0 then begin
                NLeaves += 1;
                LeafSym[NLeaves] := S;
                NodeW[NLeaves] := Hist[S + 1];
                NodeParent[NLeaves] := 0;
                NodeAlive[NLeaves] := true;
            end;
        end;
        if NLeaves < 2 then begin
            if NLeaves = 1 then
                Len[LeafSym[1] + 1] := 1;
            exit;
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
        for N := 1 to NLeaves do begin
            D := 0;
            P := N;
            while NodeParent[P] <> 0 do begin
                P := NodeParent[P];
                D += 1;
            end;
            Len[LeafSym[N] + 1] := D;
            if D > MaxD then
                MaxD := D;
        end;
        if MaxD <= MaxLen then
            exit;
        // length limit : clamp, then restore Kraft sum = 2^MaxLen exactly
        Target := Pow2B[MaxLen + 1];
        for S := 0 to AlphaSize - 1 do
            if Len[S + 1] > 0 then begin
                if Len[S + 1] > MaxLen then
                    Len[S + 1] := MaxLen;
                K += Pow2B[MaxLen - Len[S + 1] + 1];
            end;
        while K > Target do begin
            Best := -1;
            for S := 0 to AlphaSize - 1 do begin
                L := Len[S + 1];
                if (L > 0) and (L < MaxLen) then
                    if Best = -1 then
                        Best := S
                    else
                        if L > Len[Best + 1] then
                            Best := S;
            end;
            K -= Pow2B[MaxLen - Len[Best + 1]];
            Len[Best + 1] += 1;
        end;
        while K < Target do begin
            Best := -1;
            for S := 0 to AlphaSize - 1 do begin
                L := Len[S + 1];
                if L > 1 then
                    if K + Pow2B[MaxLen - L + 1] <= Target then
                        if Best = -1 then
                            Best := S
                        else
                            if L > Len[Best + 1] then
                                Best := S;
            end;
            K += Pow2B[MaxLen - Len[Best + 1] + 1];
            Len[Best + 1] -= 1;
        end;
    end;

    /// <summary>Canonical codes of Len (by length, then symbol), bit reversed for the LSB-first stream.</summary>
    local procedure CanonCodes(var Len: array[710] of Integer; var Code: array[710] of Integer; AlphaSize: Integer)
    var
        S: Integer;
        L: Integer;
        C: Integer;
        R: Integer;
        Bt: Integer;
        Next0: Integer;
    begin
        Clear(BlCount);
        for S := 1 to AlphaSize do
            if Len[S] > 0 then
                BlCount[Len[S]] += 1;
        Next0 := 0;
        for L := 1 to 15 do begin
            NextCode[L] := Next0;
            Next0 := (Next0 + BlCount[L]) * 2;
        end;
        for S := 1 to AlphaSize do begin
            L := Len[S];
            Code[S] := 0;
            if L > 0 then begin
                C := NextCode[L];
                NextCode[L] += 1;
                R := 0;
                for Bt := 1 to L do begin
                    R := R * 2 + C mod 2;
                    C := C div 2;
                end;
                Code[S] := R;
            end;
        end;
    end;

    /// <summary>
    /// Prefix code of HLen / UsedSym (after PrepareCode) : simple (HSKIP 1, symbols by increasing length) or complex
    /// (HSKIP 0, code length code lengths in ClOrder with their fixed code, then the lengths : 0-15, 17 = 3-10 zeros, never
    /// two 17 in a row so repeat counts do not stack ; trailing zeros are implied).
    /// </summary>
    local procedure WritePrefixCode(AlphaSize: Integer)
    var
        AlphaBits: Integer;
        I: Integer;
        J: Integer;
        V: Integer;
        Last: Integer;
        Run: Integer;
        R: Integer;
        NR: Integer;
        Take: Integer;
        Distinct: Integer;
        Only: Integer;
        L: Integer;
        Space: Integer;
        Prev17: Boolean;
        Single: Boolean;
    begin
        while Pow2B[AlphaBits + 1] < AlphaSize do
            AlphaBits += 1;
        if HUsed <= 4 then begin
            if HUsed = 0 then begin
                HUsed := 1;
                UsedSym[1] := 0;
            end;
            AddBits(1, 2);
            AddBits(HUsed - 1, 2);
            // by increasing length, ties by symbol (insertion sort of <= 4)
            for I := 2 to HUsed do begin
                V := UsedSym[I];
                J := I - 1;
                while J >= 1 do begin
                    if (HLen[UsedSym[J] + 1] < HLen[V + 1]) or ((HLen[UsedSym[J] + 1] = HLen[V + 1]) and (UsedSym[J] < V)) then
                        break;
                    UsedSym[J + 1] := UsedSym[J];
                    J -= 1;
                end;
                UsedSym[J + 1] := V;
            end;
            for I := 1 to HUsed do
                AddBits(UsedSym[I], AlphaBits);
            if HUsed = 4 then
                if HLen[UsedSym[1] + 1] = 1 then
                    AddBits(1, 1)
                else
                    AddBits(0, 1);
            exit;
        end;
        // code length symbols
        Last := AlphaSize - 1;
        while (Last > 0) and (HLen[Last + 1] = 0) do
            Last -= 1;
        I := 0;
        while I <= Last do
            if HLen[I + 1] = 0 then begin
                Run := 0;
                while (I + Run < Last) and (HLen[I + Run + 1] = 0) do
                    Run += 1;
                // I + Run < Last (not <=) keeps HLen[] inside bounds under AL's full evaluation ; HLen[Last + 1] <> 0 anyway
                R := Run;
                Prev17 := false;
                while R > 0 do
                    if (R >= 3) and not Prev17 then begin
                        Take := R;
                        if Take > 10 then
                            Take := 10;
                        NR += 1;
                        RleSym[NR] := 17;
                        RleExtra[NR] := Take - 3;
                        R -= Take;
                        Prev17 := true;
                    end else begin
                        NR += 1;
                        RleSym[NR] := 0;
                        RleExtra[NR] := 0;
                        R -= 1;
                        Prev17 := false;
                    end;
                I += Run;
            end else begin
                NR += 1;
                RleSym[NR] := HLen[I + 1];
                RleExtra[NR] := 0;
                I += 1;
            end;
        Clear(ClHist);
        for J := 1 to NR do
            ClHist[RleSym[J] + 1] += 1;
        for J := 1 to 18 do
            if ClHist[J] > 0 then begin
                Distinct += 1;
                Only := J;
            end;
        Single := Distinct = 1;
        if Single then begin
            Clear(ClLen);
            ClLen[Only] := 1;
        end else begin
            BuildLengths(ClHist, ClLen, 18, 5);
            CanonCodes(ClLen, ClCode, 18);
        end;
        AddBits(0, 2); // HSKIP 0
        Space := 32;
        for J := 1 to 18 do begin
            L := ClLen[ClOrder[J] + 1];
            // fixed code of the code length code lengths (LSB first)
            case L of
                0:
                    AddBits(0, 2);
                1:
                    AddBits(7, 4);
                2:
                    AddBits(3, 3);
                3:
                    AddBits(2, 2);
                4:
                    AddBits(1, 2);
                5:
                    AddBits(15, 4);
            end;
            if L > 0 then begin
                Space -= Pow2B[5 - L + 1];
                if Space <= 0 then
                    break;
            end;
        end;
        for J := 1 to NR do begin
            if not Single then
                AddBits(ClCode[RleSym[J] + 1], ClLen[RleSym[J] + 1]);
            if RleSym[J] = 17 then
                AddBits(RleExtra[J], 3);
        end;
    end;
    #endregion

    #region Compress : bit writer
    // HOT-INLINE : LSB-first bit accumulator, low N bits of Value (masked), 2 bytes per Append
    local procedure AddBits(Value: BigInteger; N: Integer)
    begin
        if N = 0 then
            exit;
        BwAcc += (Value mod Pow2B[N + 1]) * Pow2B[BwCount + 1];
        BwCount += N;
        while BwCount >= 16 do begin
            OutTB.Append(PairTbl[BwAcc mod 65536 + 1]);
            BwAcc := BwAcc div 65536;
            BwCount -= 16;
        end;
    end;

    /// <summary>Pads the last byte with zero bits.</summary>
    local procedure AlignWriter()
    begin
        if BwCount >= 8 then begin
            OutTB.Append(CharTbl[BwAcc mod 256 + 1]);
            BwAcc := BwAcc div 256;
            BwCount -= 8;
        end;
        if BwCount > 0 then
            OutTB.Append(CharTbl[BwAcc + 1]);
        BwAcc := 0;
        BwCount := 0;
    end;
    #endregion

    #region Compress : parser (codeunit "TOO ZSTD Data Compression", literals left in InText, offsets in SeqOff)

    /// <summary>
    /// Stage 6 lazy parse, stage 9 inlined (one search site, no call per position ; output identical to the stage 6-7 code).
    /// Search at Q = Pos (primary) or Pos + 1 (lazy step) : chain insertion up to Q with a rolling MinMatch-byte value,
    /// candidates = the 3 repeat offsets then up to SearchDepth chain entries (19-bit hash head, chain = position mod 1M
    /// -> previous position + 1 : AL arrays cap at 1M elements, so chains reach 1M bytes back), cheap reject on the byte
    /// just past the best length, gain = 4 x length - log2(offset value). A lazy step wins when its gain beats the current
    /// one + 4 (+ 7 at depth 2), zstd ZSTD_compressBlock_lazy_generic margins. The sequence record (EmitSequence) is inline ; literals stay in InText.
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
                SeqOff[NbSeq] := BestOff;
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
    /// The sequence record (EmitSequence) is inline ; literals stay in InText.
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
                SeqOff[NbSeq] := Off;
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
    /// Records a sequence : literal count Pos - SeqAnchor, offset coded as the decoder reads it
    /// (repeat code 1..3, shifted when LL = 0, else offset + 3) with the decoder's history update ; Pos + ML is the new anchor.
    /// </summary>
    local procedure EmitSequence(Pos: Integer; ML: Integer; Off: Integer)
    var
        LL: Integer;
        OV: Integer;
        RepCode: Integer;
    begin
        LL := Pos - SeqAnchor;
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
        SeqOff[NbSeq] := Off;
        SeqAnchor := Pos + ML;
    end;

    #endregion

    #region Decompress : meta-block
    /// <summary>
    /// One compressed meta-block of MLen bytes : block type / count codes, NPOSTFIX / NDIRECT, context modes, context maps,
    /// prefix codes, then commands (insert & copy symbol, extra bits, literals under their context tree, distance).
    /// Hot paths carry inline copies of DecodeSym and ReadBits.
    /// </summary>
    local procedure DecodeMetaBlock(MLen: Integer)
    var
        Dist: Integer;
        NPostfix: Integer;
        NDirect: Integer;
        NTreesL: Integer;
        NTreesD: Integer;
        DistAlpha: Integer;
        Produced: Integer;
        I: Integer;
        T: Integer;
        K: Integer;
        L: Integer;
        V: Integer;
        E: Integer;
        Cell: Integer;
        IC: Integer;
        CC: Integer;
        InsLen: Integer;
        CopyLen: Integer;
        Lits: Integer;
        ModeOff: Integer;
        CBase: Integer;
        DCtx: Integer;
        DCode: Integer;
        X: Integer;
        NDB: Integer;
        MaxDist: BigInteger;
        Total: BigInteger;
    begin
        TNext := 0;
        ReadBlockState(1);
        ReadBlockState(2);
        ReadBlockState(3);
        NPostfix := ReadBits(2);
        NDirect := ReadBits(4) * Pow2B[NPostfix + 1];
        for I := 1 to BlkN[1] do
            LitModes[I] := ReadBits(2);
        NTreesL := ReadVarLen() + 1;
        ReadContextMap(CMapL, 64 * BlkN[1], NTreesL);
        NTreesD := ReadVarLen() + 1;
        ReadContextMap(CMapD, 4 * BlkN[3], NTreesD);
        for T := 1 to NTreesL do
            LitTreeOff[T] := ReadPrefixCode(256);
        for T := 1 to BlkN[2] do
            CmdTreeOff[T] := ReadPrefixCode(704);
        DistAlpha := 16 + NDirect + 48 * Pow2B[NPostfix + 1];
        for T := 1 to NTreesD do
            DistTreeOff[T] := ReadPrefixCode(DistAlpha);

        while Produced < MLen do begin
            if BlkN[2] > 1 then begin
                if BlkLen[2] = 0 then
                    SwitchBlock(2);
                BlkLen[2] -= 1;
            end;
            // HOT-INLINE copy of DecodeSym(CmdTreeOff[...])
            T := CmdTreeOff[BlkType[2] + 1];
            if BrCnt < 15 then
                Refill();
            K := BrAcc mod 256;
            L := TLen[T + K + 1];
            V := TVal[T + K + 1];
            if L > 100 then begin
                K := V + (BrAcc div 256) mod Pow2B[L - 100 + 1];
                L := TLen[K + 1];
                V := TVal[K + 1];
            end;
            BrAcc := BrAcc div Pow2B[L + 1];
            BrCnt -= L;
            Cell := V div 64;
            IC := CellIns[Cell + 1] + (V div 8) mod 8;
            CC := CellCopy[Cell + 1] + V mod 8;
            // HOT-INLINE copies of ReadBits : insert extra, copy extra (<= 24 bits each)
            InsLen := InsBase[IC + 1];
            E := InsExtra[IC + 1];
            if E > 0 then begin
                if BrCnt < E then
                    Refill();
                InsLen += BrAcc mod Pow2B[E + 1];
                BrAcc := BrAcc div Pow2B[E + 1];
                BrCnt -= E;
            end;
            CopyLen := CopyBase[CC + 1];
            E := CopyExtra[CC + 1];
            if E > 0 then begin
                if BrCnt < E then
                    Refill();
                CopyLen += BrAcc mod Pow2B[E + 1];
                BrAcc := BrAcc div Pow2B[E + 1];
                BrCnt -= E;
            end;

            // literals : the meta-block may end inside them
            Lits := InsLen;
            if Lits > MLen - Produced then
                Lits := MLen - Produced;
            ModeOff := LitModes[BlkType[1] + 1] * 256;
            CBase := BlkType[1] * 64;
            if BlkN[1] = 1 then
                for I := 1 to Lits do begin
                    // HOT-INLINE copy of DecodeSym : tree of the context of the 2 previous bytes
                    T := LitTreeOff[CMapL[CBase + OrTbl[CtxLut[ModeOff + P1 + 1] * 64 + CtxLut2[ModeOff + P2 + 1] + 1] + 1] + 1];
                    if BrCnt < 15 then
                        Refill();
                    K := BrAcc mod 256;
                    L := TLen[T + K + 1];
                    V := TVal[T + K + 1];
                    if L > 100 then begin
                        K := V + (BrAcc div 256) mod Pow2B[L - 100 + 1];
                        L := TLen[K + 1];
                        V := TVal[K + 1];
                    end;
                    BrAcc := BrAcc div Pow2B[L + 1];
                    BrCnt -= L;
                    // 2 literals per Append
                    if LitPend < 0 then
                        LitPend := V
                    else begin
                        OutTB.Append(PairTbl[LitPend + V * 256 + 1]);
                        LitPend := -1;
                    end;
                    P2 := P1;
                    P1 := V;
                end
            else
                for I := 1 to Lits do begin
                    if BlkLen[1] = 0 then begin
                        SwitchBlock(1);
                        ModeOff := LitModes[BlkType[1] + 1] * 256;
                        CBase := BlkType[1] * 64;
                    end;
                    BlkLen[1] -= 1;
                    V := DecodeSym(LitTreeOff[CMapL[CBase + OrTbl[CtxLut[ModeOff + P1 + 1] * 64 + CtxLut2[ModeOff + P2 + 1] + 1] + 1] + 1]);
                    if LitPend < 0 then
                        LitPend := V
                    else begin
                        OutTB.Append(PairTbl[LitPend + V * 256 + 1]);
                        LitPend := -1;
                    end;
                    P2 := P1;
                    P1 := V;
                end;
            Produced += Lits;

            if Produced < MLen then begin
                // distance : implicit last distance (codes 0-127), short code, direct, or extra bits
                if Cell < 2 then begin
                    DCode := 0;
                    Dist := Rb[(RbIdx + 3) mod 4 + 1];
                end else begin
                    if BlkN[3] > 1 then begin
                        if BlkLen[3] = 0 then
                            SwitchBlock(3);
                        BlkLen[3] -= 1;
                    end;
                    if CopyLen > 4 then
                        DCtx := 3
                    else
                        DCtx := CopyLen - 2;
                    DCode := DecodeSym(DistTreeOff[CMapD[BlkType[3] * 4 + DCtx + 1] + 1]);
                    if DCode < 16 then
                        Dist := ShortDistance(DCode)
                    else
                        if DCode < 16 + NDirect then
                            Dist := DCode - 15
                        else begin
                            X := DCode - NDirect - 16;
                            NDB := 1 + X div Pow2B[NPostfix + 2];
                            Dist := ((2 + (X div Pow2B[NPostfix + 1]) mod 2) * Pow2B[NDB + 1] - 4 + ReadBits(NDB)) * Pow2B[NPostfix + 1] +
                                X mod Pow2B[NPostfix + 1] + NDirect + 1;
                        end;
                end;
                FlushLiteral();
                Total := OutDropped + OutTB.Length();
                MaxDist := MaxBack;
                if Total < MaxDist then
                    MaxDist := Total;
                if Dist > MaxDist then
                    Produced += DictionaryWord(CopyLen, Dist - MaxDist - 1)
                else begin
                    if DCode <> 0 then begin
                        Rb[RbIdx + 1] := Dist;
                        RbIdx := (RbIdx + 1) mod 4;
                    end;
                    CopyMatch(Dist, CopyLen);
                    Produced += CopyLen;
                end;
                if Produced > MLen then
                    Error(CorruptErr);
                if OutTB.Length() > MaxBack + 4194304 then
                    SlideWindow();
            end;
        end;
    end;

    local procedure ShortDistance(DCode: Integer) Dist: Integer
    var
        Last: Integer;
        Second: Integer;
    begin
        Last := Rb[(RbIdx + 3) mod 4 + 1];
        Second := Rb[(RbIdx + 2) mod 4 + 1];
        case DCode of
            0:
                Dist := Last;
            1:
                Dist := Second;
            2:
                Dist := Rb[(RbIdx + 1) mod 4 + 1];
            3:
                Dist := Rb[RbIdx + 1];
            4:
                Dist := Last - 1;
            5:
                Dist := Last + 1;
            6:
                Dist := Last - 2;
            7:
                Dist := Last + 2;
            8:
                Dist := Last - 3;
            9:
                Dist := Last + 3;
            10:
                Dist := Second - 1;
            11:
                Dist := Second + 1;
            12:
                Dist := Second - 2;
            13:
                Dist := Second + 2;
            14:
                Dist := Second - 3;
            15:
                Dist := Second + 3;
        end;
        if Dist <= 0 then
            Error(CorruptErr);
    end;

    /// <summary>Copies Len bytes from Dist back : one ToText + Append, or a doubling pattern when Dist < Len ; P1 / P2 follow.</summary>
    local procedure CopyMatch(Dist: Integer; Len: Integer)
    var
        Chunk: Text;
        Rem: Integer;
        N: Integer;
    begin
        if Dist > OutTB.Length() then
            Error(CorruptErr);
        if Dist >= Len then begin
            Chunk := OutTB.ToText(OutTB.Length() - Dist + 1, Len);
            OutTB.Append(Chunk);
        end else begin
            Chunk := OutTB.ToText(OutTB.Length() - Dist + 1, Dist);
            Rem := Len;
            while Rem > 0 do begin
                N := StrLen(Chunk);
                if N > Rem then begin
                    Chunk := Chunk.Substring(1, Rem);
                    N := Rem;
                end;
                OutTB.Append(Chunk);
                Rem -= N;
                if Rem > N then
                    Chunk += Chunk; // still a whole number of periods
            end;
        end;
        N := StrLen(Chunk);
        if N >= 2 then begin
            P1 := Chunk[N];
            P2 := Chunk[N - 1];
        end else
            SetTail();
    end;

    /// <summary>Static dictionary word (length Len 4..24, WordId) through its transform ; returns the bytes written.</summary>
    local procedure DictionaryWord(Len: Integer; WordId: BigInteger): Integer
    var
        Word: Text;
        NB: Integer;
        Idx: Integer;
        Tr: Integer;
        N: Integer;
    begin
        if (Len < 4) or (Len > 24) then
            Error(CorruptErr);
        LoadDictionary();
        NB := NDBits[Len + 1];
        Idx := WordId mod Pow2B[NB + 1];
        Tr := WordId div Pow2B[NB + 1];
        if Tr >= 121 then
            Error(CorruptErr);
        Word := ApplyTransform(DictText.Substring(DOffset[Len + 1] + Idx * Len + 1, Len), Tr);
        N := StrLen(Word);
        if N > 0 then
            OutTB.Append(Word);
        if N >= 2 then begin
            P1 := Word[N];
            P2 := Word[N - 1];
        end else
            SetTail();
        exit(N);
    end;

    /// <summary>RFC 7932 transform : omit first / last 1-9, uppercase first / all (UTF-8 aware), prefix + suffix.</summary>
    local procedure ApplyTransform(Word: Text; Tr: Integer): Text
    var
        WType: Integer;
        I: Integer;
    begin
        WType := TrType[Tr + 1];
        if (WType >= 1) and (WType <= 9) then
            if WType >= StrLen(Word) then
                Word := ''
            else
                Word := Word.Substring(1, StrLen(Word) - WType);
        if (WType >= 12) and (WType <= 20) then
            if WType - 11 >= StrLen(Word) then
                Word := ''
            else
                Word := Word.Substring(WType - 11 + 1);
        if (WType = 10) and (StrLen(Word) > 0) then
            UpperAt(Word, 1);
        if WType = 11 then begin
            I := 1;
            while I <= StrLen(Word) do
                I += UpperAt(Word, I);
        end;
        exit(PrefixSuffix[TrPre[Tr + 1] + 1] + Word + PrefixSuffix[TrSuf[Tr + 1] + 1]);
    end;

    /// <summary>brotli ToUpperCase at I : ASCII a-z xor 32, 2-byte UTF-8 : 2nd byte xor 32, else 3rd byte xor 5 ; returns the step.</summary>
    local procedure UpperAt(var Word: Text; I: Integer): Integer
    var
        C: Integer;
        Ch: Char;
    begin
        C := Word[I];
        if C < 192 then begin
            if (C >= 97) and (C <= 122) then begin
                Ch := C - 32;
                Word[I] := Ch;
            end;
            exit(1);
        end;
        if C < 224 then begin
            if I + 1 <= StrLen(Word) then begin
                C := Word[I + 1];
                if (C div 32) mod 2 = 1 then
                    Ch := C - 32
                else
                    Ch := C + 32;
                Word[I + 1] := Ch;
            end;
            exit(2);
        end;
        if I + 2 <= StrLen(Word) then begin
            C := Word[I + 2];
            // xor 5 : flip bits 0 and 2
            if C mod 2 = 1 then
                C -= 1
            else
                C += 1;
            if (C div 4) mod 2 = 1 then
                C -= 4
            else
                C += 4;
            Ch := C;
            Word[I + 2] := Ch;
        end;
        exit(3);
    end;

    local procedure LoadDictionary()
    var
        InStr: InStream;
    begin
        if DictReady then
            exit;
        if not NavApp.GetResource('brotli-dictionary.bin', InStr) then
            Error(DictErr);
        Latin1.ISO88591();
        Reader.StreamReader(InStr, Latin1);
        DictText := Reader.ReadToEnd();
        if StrLen(DictText) <> 122784 then
            Error(DictErr);
        DictReady := true;
    end;

    /// <summary>Uncompressed meta-block : byte aligned raw bytes.</summary>
    local procedure CopyUncompressed(MLen: Integer)
    begin
        AlignReader();
        if InPos + MLen - 1 > InLen then
            Error(CorruptErr);
        FlushLiteral();
        OutTB.Append(InText.Substring(InPos, MLen));
        InPos += MLen;
        SetTail();
        if OutTB.Length() > MaxBack + 4194304 then
            SlideWindow();
    end;

    local procedure FlushLiteral()
    begin
        if LitPend >= 0 then begin
            OutTB.Append(CharTbl[LitPend + 1]);
            LitPend := -1;
        end;
    end;

    /// <summary>P1 / P2 = the last 2 bytes written (0 before the start).</summary>
    local procedure SetTail()
    var
        Tail: Text;
        N: Integer;
    begin
        FlushLiteral();
        N := OutTB.Length();
        P1 := 0;
        P2 := 0;
        if N >= 2 then begin
            Tail := OutTB.ToText(N - 1, 2);
            P2 := Tail[1];
            P1 := Tail[2];
        end else
            if N = 1 then begin
                Tail := OutTB.ToText(1, 1);
                P1 := Tail[1];
            end;
    end;

    /// <summary>Keeps at least MaxBack bytes in OutTB : older bytes are written once and dropped.</summary>
    local procedure SlideWindow()
    var
        Excess: Integer;
    begin
        FlushLiteral();
        Excess := OutTB.Length() - MaxBack;
        if Excess <= 0 then
            exit;
        Writer.Write(OutTB.ToText(1, Excess));
        OutTB.Remove(1, Excess);
        OutDropped += Excess;
    end;
    #endregion

    #region Decompress : block types, context maps
    local procedure ReadBlockState(Cat: Integer)
    begin
        BlkN[Cat] := ReadVarLen() + 1;
        BlkType[Cat] := 0;
        BlkPrev[Cat] := 1;
        BlkLen[Cat] := 16777216;
        if BlkN[Cat] >= 2 then begin
            BlkTypeTree[Cat] := ReadPrefixCode(BlkN[Cat] + 2);
            BlkLenTree[Cat] := ReadPrefixCode(26);
            BlkLen[Cat] := ReadBlockLen(BlkLenTree[Cat]);
        end;
    end;

    local procedure ReadBlockLen(Tree: Integer): Integer
    var
        C: Integer;
    begin
        C := DecodeSym(Tree);
        exit(BlkBase[C + 1] + ReadBits(BlkExtra[C + 1]));
    end;

    local procedure SwitchBlock(Cat: Integer)
    var
        C: Integer;
        T: Integer;
    begin
        C := DecodeSym(BlkTypeTree[Cat]);
        if C = 0 then
            T := BlkPrev[Cat]
        else
            if C = 1 then
                T := (BlkType[Cat] + 1) mod BlkN[Cat]
            else
                T := C - 2;
        if T >= BlkN[Cat] then
            T -= BlkN[Cat];
        BlkPrev[Cat] := BlkType[Cat];
        BlkType[Cat] := T;
        BlkLen[Cat] := ReadBlockLen(BlkLenTree[Cat]);
    end;

    local procedure ReadVarLen(): Integer
    var
        N: Integer;
    begin
        if ReadBits(1) = 0 then
            exit(0);
        N := ReadBits(3);
        if N = 0 then
            exit(1);
        exit(Pow2B[N + 1] + ReadBits(N));
    end;

    /// <summary>Context map of Size entries : RLEMAX, prefix code, zero runs, optional inverse move-to-front.</summary>
    local procedure ReadContextMap(var Map: array[16384] of Integer; Size: Integer; NTreesX: Integer)
    var
        RleMax: Integer;
        Tree: Integer;
        I: Integer;
        J: Integer;
        C: Integer;
        Run: Integer;
        Idx: Integer;
        V: Integer;
    begin
        for I := 1 to Size do
            Map[I] := 0;
        if NTreesX = 1 then
            exit;
        if ReadBits(1) = 1 then
            RleMax := ReadBits(4) + 1;
        Tree := ReadPrefixCode(NTreesX + RleMax);
        I := 1;
        while I <= Size do begin
            C := DecodeSym(Tree);
            if C = 0 then
                I += 1
            else
                if C <= RleMax then begin
                    Run := Pow2B[C + 1] + ReadBits(C);
                    if I + Run - 1 > Size then
                        Error(CorruptErr);
                    I += Run; // already 0
                end else begin
                    Map[I] := C - RleMax;
                    I += 1;
                end;
        end;
        if ReadBits(1) = 1 then begin
            for J := 1 to 256 do
                Mtf[J] := J - 1;
            for I := 1 to Size do begin
                Idx := Map[I];
                V := Mtf[Idx + 1];
                Map[I] := V;
                for J := Idx downto 1 do
                    Mtf[J + 1] := Mtf[J];
                Mtf[1] := V;
            end;
        end;
    end;
    #endregion

    #region Decompress : prefix codes
    /// <summary>Reads a prefix code over AlphaSize symbols (simple or complex, RFC 7932 3.4 / 3.5) and builds its table ; returns the table offset.</summary>
    local procedure ReadPrefixCode(AlphaSize: Integer): Integer
    var
        AlphaBits: Integer;
        HSkip: Integer;
        NSym: Integer;
        I: Integer;
        J: Integer;
        Peek: Integer;
        V: Integer;
        Space: Integer;
        Num: Integer;
        ClTree: Integer;
        Sym: Integer;
        C: Integer;
        PrevLen: Integer;
        RepeatCnt: Integer;
        RepeatLen: Integer;
        Space2: Integer;
        ExtraB: Integer;
        NewLen: Integer;
        Old: Integer;
        Cnt: Integer;
    begin
        while Pow2B[AlphaBits + 1] < AlphaSize do
            AlphaBits += 1;
        for I := 1 to AlphaSize do
            Lens[I] := 0;
        HSkip := ReadBits(2);
        if HSkip = 1 then begin
            NSym := ReadBits(2) + 1;
            for I := 1 to NSym do begin
                SimpleSym[I] := ReadBits(AlphaBits);
                if SimpleSym[I] >= AlphaSize then
                    Error(CorruptErr);
                for J := 1 to I - 1 do
                    if SimpleSym[J] = SimpleSym[I] then
                        Error(CorruptErr);
            end;
            case NSym of
                1:
                    Lens[SimpleSym[1] + 1] := 1; // single symbol : 0 bits (BuildTable)
                2:
                    begin
                        Lens[SimpleSym[1] + 1] := 1;
                        Lens[SimpleSym[2] + 1] := 1;
                    end;
                3:
                    begin
                        Lens[SimpleSym[1] + 1] := 1;
                        Lens[SimpleSym[2] + 1] := 2;
                        Lens[SimpleSym[3] + 1] := 2;
                    end;
                4:
                    if ReadBits(1) = 1 then begin
                        Lens[SimpleSym[1] + 1] := 1;
                        Lens[SimpleSym[2] + 1] := 2;
                        Lens[SimpleSym[3] + 1] := 3;
                        Lens[SimpleSym[4] + 1] := 3;
                    end else
                        for I := 1 to 4 do
                            Lens[SimpleSym[I] + 1] := 2;
            end;
            exit(BuildTable(AlphaSize));
        end;
        // complex : code length code lengths (fixed prefix code, ClOrder), then the lengths with repeat codes 16 / 17
        Clear(DClLen);
        Space := 32;
        for I := HSkip + 1 to 18 do begin
            if BrCnt < 4 then
                Refill();
            Peek := BrAcc mod 16;
            case Peek of
                0, 4, 8, 12:
                    V := 0;
                1, 5, 9, 13:
                    V := 4;
                2, 6, 10, 14:
                    V := 3;
                3, 11:
                    V := 2;
                7:
                    V := 1;
                15:
                    V := 5;
            end;
            case V of
                0, 3, 4:
                    J := 2;
                2:
                    J := 3;
                1, 5:
                    J := 4;
            end;
            BrAcc := BrAcc div Pow2B[J + 1];
            BrCnt -= J;
            DClLen[ClOrder[I] + 1] := V;
            if V <> 0 then begin
                Space -= Pow2B[5 - V + 1];
                Num += 1;
                if Space <= 0 then
                    break;
            end;
        end;
        if not ((Num = 1) or (Space = 0)) then
            Error(CorruptErr);
        for I := 1 to 18 do
            Lens[I] := DClLen[I];
        ClTree := BuildTable(18);
        for I := 1 to AlphaSize do
            Lens[I] := 0;
        PrevLen := 8;
        Space2 := 32768;
        while (Sym < AlphaSize) and (Space2 > 0) do begin
            C := DecodeSym(ClTree);
            if C < 16 then begin
                RepeatCnt := 0;
                Lens[Sym + 1] := C;
                Sym += 1;
                if C <> 0 then begin
                    PrevLen := C;
                    Space2 -= Pow2B[15 - C + 1];
                end;
            end else begin
                if C = 16 then begin
                    ExtraB := 2;
                    NewLen := PrevLen;
                end else begin
                    ExtraB := 3;
                    NewLen := 0;
                end;
                if RepeatLen <> NewLen then begin
                    RepeatCnt := 0;
                    RepeatLen := NewLen;
                end;
                Old := RepeatCnt;
                if RepeatCnt > 0 then
                    RepeatCnt := (RepeatCnt - 2) * Pow2B[ExtraB + 1];
                RepeatCnt += ReadBits(ExtraB) + 3;
                Cnt := RepeatCnt - Old;
                if Sym + Cnt > AlphaSize then
                    Error(CorruptErr);
                for J := 1 to Cnt do begin
                    Lens[Sym + 1] := RepeatLen;
                    Sym += 1;
                end;
                if RepeatLen <> 0 then
                    Space2 -= Cnt * Pow2B[15 - RepeatLen + 1];
            end;
        end;
        if Space2 <> 0 then
            Error(CorruptErr);
        exit(BuildTable(AlphaSize));
    end;

    /// <summary>
    /// Table of Lens (AlphaSize symbols) at TNext : 256-entry root indexed by the next 8 bits (LSB first) ; codes longer
    /// than 8 bits : root entry length 100 + sub bits, value = sub table offset. One used symbol : 0 bits.
    /// </summary>
    local procedure BuildTable(AlphaSize: Integer) Base: Integer
    var
        Used: Integer;
        Only: Integer;
        S: Integer;
        L: Integer;
        C: Integer;
        R: Integer;
        K: Integer;
        Total: Integer;
    begin
        Base := TNext;
        for S := 1 to AlphaSize do
            if Lens[S] > 0 then begin
                Used += 1;
                Only := S - 1;
            end;
        if Used = 0 then
            Error(CorruptErr);
        if Base + 256 + 32768 > 1000000 then
            Error(CorruptErr);
        if Used = 1 then begin
            for K := 1 to 256 do begin
                TLen[Base + K] := 0;
                TVal[Base + K] := Only;
            end;
            TNext := Base + 256;
            exit(Base);
        end;
        CanonCodes(Lens, Codes, AlphaSize);
        Clear(SubBits);
        for S := 1 to AlphaSize do
            if Lens[S] > 8 then begin
                R := Codes[S] mod 256;
                if Lens[S] - 8 > SubBits[R + 1] then
                    SubBits[R + 1] := Lens[S] - 8;
            end;
        Total := 256;
        for R := 1 to 256 do
            if SubBits[R] > 0 then begin
                SubOff[R] := Base + Total;
                Total += Pow2B[SubBits[R] + 1];
                TLen[Base + R] := 100 + SubBits[R];
                TVal[Base + R] := SubOff[R];
            end;
        if Base + Total > 1000000 then
            Error(CorruptErr);
        for S := 1 to AlphaSize do begin
            L := Lens[S];
            if L > 0 then begin
                C := Codes[S];
                if L <= 8 then begin
                    K := C;
                    while K < 256 do begin
                        TLen[Base + K + 1] := L;
                        TVal[Base + K + 1] := S - 1;
                        K += Pow2B[L + 1];
                    end;
                end else begin
                    R := C mod 256;
                    K := C div 256;
                    while K < Pow2B[SubBits[R + 1] + 1] do begin
                        TLen[SubOff[R + 1] + K + 1] := L;
                        TVal[SubOff[R + 1] + K + 1] := S - 1;
                        K += Pow2B[L - 8 + 1];
                    end;
                end;
            end;
        end;
        TNext := Base + Total;
    end;

    // HOT-INLINE (inline copies in DecodeMetaBlock) : next symbol of the table at T
    local procedure DecodeSym(T: Integer): Integer
    var
        K: Integer;
        L: Integer;
        V: Integer;
    begin
        if BrCnt < 15 then
            Refill();
        K := BrAcc mod 256;
        L := TLen[T + K + 1];
        V := TVal[T + K + 1];
        if L > 100 then begin
            K := V + (BrAcc div 256) mod Pow2B[L - 100 + 1];
            L := TLen[K + 1];
            V := TVal[K + 1];
        end;
        BrAcc := BrAcc div Pow2B[L + 1];
        BrCnt -= L;
        exit(V);
    end;
    #endregion

    #region Decompress : bit reader
    /// <summary>LSB-first container : bytes loaded while <= 48 bits are held (past the input end : zero bytes).</summary>
    local procedure Refill()
    var
        C: Integer;
    begin
        while BrCnt <= 48 do begin
            if InPos <= InLen then begin
                C := InText[InPos];
                BrAcc += C * Pow2B[BrCnt + 1];
            end;
            InPos += 1;
            BrCnt += 8;
        end;
    end;

    // HOT-INLINE : N <= 24 bits
    local procedure ReadBits(N: Integer): Integer
    var
        V: Integer;
    begin
        if N = 0 then
            exit(0);
        if BrCnt < N then
            Refill();
        V := BrAcc mod Pow2B[N + 1];
        BrAcc := BrAcc div Pow2B[N + 1];
        BrCnt -= N;
        exit(V);
    end;

    /// <summary>Drops the bits up to the byte boundary and gives the whole buffered bytes back to InPos.</summary>
    local procedure AlignReader()
    begin
        ReadBits(BrCnt mod 8);
        InPos -= BrCnt div 8;
        BrAcc := 0;
        BrCnt := 0;
    end;
    #endregion
}
