/*
    C# port of the Compress side of codeunit 51150 "TOO ZSTD Data Compression" (TOOZSTDDataCompression.Codeunit.al).
    Purpose : measure the compression ratio of the AL encoder off-BC, and try parser settings before porting them back.

    Port rules (keep the output byte-identical to the AL) :
    - AL 1-based indexing is kept everywhere : T[i] = InText[i] (T[0] unused, T[InLen + 1] = guard char 0), arrays are
      sized N + 1 and indexed [1..N] exactly as in AL, so each statement maps 1:1 to its AL line.
    - Text.Substring compares = span compares ; TextBuilder = ByteBuilder.
    - AL BigInteger = long, AL Integer = int ; div / mod = C# / % (all operands are non-negative where it matters).
    - HOT-INLINE copies of the AL are kept inline (same code order), helper calls are free in C# but the order of
      side effects on tables must not change.
    Counters (Stats) feed the AL time model of the README : ms/MB = 45 + 0.079 inserts + 0.364 positions
    + 0.041 candidates + 0.0076 bytes (thousands per raw MB).
*/
namespace ZstdAlPort;

public enum ZstdLevel { Fast = 0, Medium = 1, Heavy = 2 }

public enum ZstdProfile { General = 0, ColumnData = 1 }

public sealed class Stats
{
    public long Inserts;     // chain insertions (ParseLazy) / table writes (ParseDoubleFast)
    public long Positions;   // parse loop iterations
    public long Candidates;  // chain candidates visited / double fast candidates tried
    public long Bytes;       // per-byte match extension steps
    public long RawBytes;
    // entropy stage breakdown (emitted compressed blocks) : sizes in bytes, ideal = order-0 Shannon bits
    public long Blocks, Lits, LitBytes, Seqs, SeqHdrBytes, SeqBytes; public double LitIdealBits, SeqIdealBits;

    public void Add(Stats o) { Blocks += o.Blocks; Lits += o.Lits; LitBytes += o.LitBytes; Seqs += o.Seqs; SeqHdrBytes += o.SeqHdrBytes; SeqBytes += o.SeqBytes; LitIdealBits += o.LitIdealBits; SeqIdealBits += o.SeqIdealBits; Inserts += o.Inserts; Positions += o.Positions; Candidates += o.Candidates; Bytes += o.Bytes; RawBytes += o.RawBytes; }

    /// <summary>README time model, AL ms for the counted input.</summary>
    public double EstimatedAlMs()
    {
        if (RawBytes == 0) return 0;
        double mb = RawBytes / 1048576.0;
        double k = 1000.0 * mb; // counters in thousands per raw MB
        return mb * 45 + 0.079 * Inserts / k * mb + 0.364 * Positions / k * mb + 0.041 * Candidates / k * mb + 0.0076 * Bytes / k * mb;
    }
}

/// <summary>SetTuning equivalent : -1 keeps the level default.</summary>
public sealed class Tuning
{
    public int MinMatch = -1, SearchDepth = -1, LazyDepth = -1, LdmMinInput = -1, MaxInsertLen = -1, MaxLazyLen = -1, NiceLen = -1;
    public bool SkipRunInsert;
    // experiment knobs (not in the AL SetTuning) : -1 = level default
    public int RepChecks = -1, SpeedMode = -1, DfShortMul = -1, Ldm = -1; // DfShortMul : 1 = 5-byte short hash, 0 = 4-byte
}

public sealed class ByteBuilder
{
    byte[] buf = new byte[1 << 16];
    int len;
    public int Length => len;
    public void Clear() => len = 0;
    void Grow(int need) { if (len + need > buf.Length) Array.Resize(ref buf, Math.Max(buf.Length * 2, len + need)); }
    public void Append(byte b) { Grow(1); buf[len++] = b; }
    public void Append(byte[] src, int start, int count) { if (count <= 0) return; Grow(count); Buffer.BlockCopy(src, start, buf, len, count); len += count; }
    public void Append(byte[] src) => Append(src, 0, src.Length);
    public void Truncate(int newLen) => len = newLen;
    public byte[] ToArray() { var r = new byte[len]; Buffer.BlockCopy(buf, 0, r, 0, len); return r; }
}

public sealed class ZstdAlEncoder
{
    // ---------- Shared ----------
    byte[] T = Array.Empty<byte>(); // InText, 1-based, guard char at InLen + 1
    int InLen;
    readonly ByteBuilder OutTB = new();
    byte[] Lit = Array.Empty<byte>(); // LitText, 1-based
    long Rep1, Rep2, Rep3;
    readonly int[] LLBase = new int[54], LLBits = new int[54], MLBase = new int[54], MLBits = new int[54];
    readonly long[] Pow2B = new long[65];
    bool TablesReady;
    readonly int[] NormCount = new int[257];
    // ---------- Compress ----------
    readonly ByteBuilder BlockTB = new(), LitTB = new();
    readonly int[] LitHist = new int[257], HufLen = new int[257], HufCode = new int[257], HufWeight = new int[257];
    int HufMax;
    readonly int[] LeafSym = new int[257], NodeW = new int[513], NodeParent = new int[513];
    readonly bool[] NodeAlive = new bool[513];
    int MaxStage, WindowLog, WindowSize;
    readonly int[] Head = new int[524289];
    readonly int[] Chain = new int[1000001];
    int NextIns, PosBase;
    long InsV; int InsVPos;
    int SeqAnchor, FBLen, FBOff, FBGain;
    int SearchDepth, LazyDepth;
    bool DoubleFast;
    readonly int[] DfLong = new int[524289], DfShort = new int[524289];
    bool SpeedMode;
    int RepCheckCount; // repeat offsets tried per search (ParseLazy)
    long DfShortMul; // ParseDoubleFast short hash : 2^32 = 5 bytes (VS + low byte of VL), 0 = 4 bytes (VS)
    int MinMatch; long HashMul; int LdmMinInput, MaxInsertLen, MaxLazyLen, NiceLen; bool SkipRunInsert;
    Tuning Tune;
    readonly int[] HBTbl = new int[1025];
    readonly int[] LdmPos = new int[524289], LdmTag = new int[524289], LdmNext = new int[131073];
    readonly int[] Gear = new int[257];
    int LdmCount;
    readonly int[] LdmStart = new int[2101], LdmLen = new int[2101], LdmOff = new int[2101];
    int LitCount, NbSeq;
    readonly int[] SeqLL = new int[44001], SeqML = new int[44001], SeqOfv = new int[44001];
    readonly int[] SeqLLCode = new int[44001], SeqMLCode = new int[44001], SeqOFCode = new int[44001];
    readonly int[] LLCodeTbl = new int[65], MLCodeTbl = new int[129];
    int PRep1, PRep2, PRep3;
    readonly int[] SlotMode = new int[4], SlotMax = new int[4], SlotTL = new int[4], SlotRleSym = new int[4];
    readonly int[] SlotNorm = new int[193];
    readonly bool[] ComValid = new bool[4], ComRle = new bool[4];
    readonly int[] ComMax = new int[4], ComTL = new int[4];
    readonly int[] ComNorm = new int[193];
    readonly int[] Log2Q8 = new int[1025];
    long BwAcc; int BwCount;
    readonly int[] CState = new int[2049], DeltaNbBits = new int[257], DeltaFindState = new int[257], CTableLog = new int[5];
    readonly int[] HistCount = new int[257], SeqHist = new int[193], Cumul = new int[258], TableSymbol = new int[513];

    public Stats Stats = new();

    static readonly int[] LLBaseTok = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
    static readonly int[] LLBitsTok = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static readonly int[] MLBaseTok = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539 };
    static readonly int[] MLBitsTok = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    static readonly int[] LLNormTok = { 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1 };
    static readonly int[] OFNormTok = { 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };
    static readonly int[] MLNormTok = { 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1 };

    public void SetTuning(Tuning t) => Tune = t;

    // ======================================================================================== Compress
    public byte[] Compress(byte[] input, ZstdLevel level, ZstdProfile profile = ZstdProfile.General)
    {
        bool singleSegment;
        Stats = new Stats { RawBytes = input.Length };
        InitTables();
        InLen = input.Length;
        ApplyLevel(level, profile);
        T = new byte[InLen + 2 + 64]; // [0] unused, [InLen + 1] guard char ; extra zeros never read by the AL paths
        Buffer.BlockCopy(input, 0, T, 1, InLen);
        if (PosBase > 2000000000 - InLen)
        {
            Array.Clear(Head); Array.Clear(Chain); Array.Clear(DfLong); Array.Clear(DfShort);
            Array.Clear(LdmPos); Array.Clear(LdmTag); Array.Clear(LdmNext);
            PosBase = 0;
        }
        if (MaxStage >= 7 && InLen > LdmMinInput)
            Array.Clear(LdmNext);
        OutTB.Clear();
        NextIns = 0;
        InsVPos = -1;
        Rep1 = 1; Rep2 = 4; Rep3 = 8;
        Array.Clear(ComValid);
        WindowSize = (int)Pow2B[WindowLog + 1];
        singleSegment = InLen <= WindowSize;
        WriteFrameHeader(singleSegment);
        if (singleSegment || WindowSize > 131072) WriteBlocks(131072); else WriteBlocks(WindowSize);
        var result = OutTB.ToArray();
        PosBase += InLen + 1;
        T = Array.Empty<byte>();
        Lit = Array.Empty<byte>();
        OutTB.Clear(); BlockTB.Clear(); LitTB.Clear();
        return result;
    }

    void InitTables()
    {
        if (TablesReady) return;
        Pow2B[1] = 1;
        for (int i = 2; i <= 63; i++) Pow2B[i] = Pow2B[i - 1] * 2;
        for (int i = 0; i < LLBaseTok.Length; i++) { LLBase[i + 1] = LLBaseTok[i]; LLBits[i + 1] = LLBitsTok[i]; }
        for (int i = 0; i < MLBaseTok.Length; i++) { MLBase[i + 1] = MLBaseTok[i]; MLBits[i + 1] = MLBitsTok[i]; }
        HBTbl[1] = 0;
        for (int i = 2; i <= 1024; i++) HBTbl[i] = HBTbl[i / 2] + 1;
        long lcg = 12345;
        for (int i = 1; i <= 256; i++)
        {
            lcg = (lcg * 1103515245 + 12345) % 2147483648L;
            long code = lcg / 32768;
            lcg = (lcg * 1103515245 + 12345) % 2147483648L;
            Gear[i] = (int)(code * 32768 + lcg / 65536);
        }
        for (int i = 1; i <= 1024; i++)
        {
            int code = HighBit(i);
            long m = i * 65536L / Pow2B[code + 1];
            int frac = 0;
            for (int k = 1; k <= 8; k++)
            {
                m = m * m / 65536;
                frac *= 2;
                if (m >= 131072) { frac += 1; m /= 2; }
            }
            Log2Q8[i] = code * 256 + frac;
        }
        int c = 0;
        for (int i = 0; i <= 63; i++) { while (c < 35 && LLBase[c + 2] <= i) c++; LLCodeTbl[i + 1] = c; }
        c = 0;
        for (int i = 0; i <= 127; i++) { while (c < 52 && MLBase[c + 2] - 3 <= i) c++; MLCodeTbl[i + 1] = c; }
        TablesReady = true;
    }

    static int HighBit(int value) { int r = 0; while (value >= 2) { value /= 2; r++; } return r; }

    void SetPredefinedNorm(int kind, out int maxSymbol, out int tableLog)
    {
        int[] v = kind switch { 1 => LLNormTok, 2 => OFNormTok, _ => MLNormTok };
        tableLog = kind == 2 ? 5 : 6;
        maxSymbol = v.Length - 1;
        for (int s = 0; s < v.Length; s++) NormCount[s + 1] = v[s];
    }

    /// <summary>
    /// Parser settings behind each level and profile.
    /// ColumnData : the settings tuned on column-oriented table exports (unchanged, see the AL ApplyLevel comment).
    /// General (default) : tuned on general files (JSON, XML, CSV, text, source, PDF, enwik8) by input size, because the
    /// best hashed length depends on how many chain candidates compete :
    ///   <= 64 KB : MinMatch 4 ; <= 256 KB : MinMatch 5 (both : deep search, cheap in absolute time, no LDM) ;
    ///   larger : MinMatch 6 like ColumnData, Fast with a 4-byte short hash, Medium depth 16 + 3 repeat checks,
    ///   Heavy depth 24 + lazy 2.
    /// </summary>
    void ApplyLevel(ZstdLevel level, ZstdProfile profile)
    {
        WindowLog = 24;
        SearchDepth = 16;
        LazyDepth = 1;
        MinMatch = 6;
        LdmMinInput = 0;
        SkipRunInsert = false;
        DfShortMul = 4294967296L;
        switch (level)
        {
            case ZstdLevel.Fast: MaxStage = 6; DoubleFast = true; SpeedMode = true; break;
            case ZstdLevel.Medium: MaxStage = 7; DoubleFast = false; SpeedMode = true; SearchDepth = 8; SkipRunInsert = true; break;
            case ZstdLevel.Heavy: MaxStage = 7; DoubleFast = false; SpeedMode = false; break;
            default: throw new ArgumentException("Invalid zstd compression settings.");
        }
        if (SpeedMode) { MaxInsertLen = 32; MaxLazyLen = 32; NiceLen = 128; }
        else { MaxInsertLen = 128; MaxLazyLen = 0; NiceLen = 0; }
        RepCheckCount = SpeedMode ? 1 : 3;
        if (profile == ZstdProfile.General)
        {
            if (InLen <= 262144)
            {
                // small input : lazy parse at every level, no LDM (the chains reach the whole input)
                MaxStage = 6;
                DoubleFast = false;
                RepCheckCount = 3;
                MinMatch = InLen <= 65536 ? 4 : 5;
                switch (level)
                {
                    case ZstdLevel.Fast: SpeedMode = true; SearchDepth = 8; SkipRunInsert = true; MaxInsertLen = 32; MaxLazyLen = 32; NiceLen = 128; break;
                    case ZstdLevel.Medium: SpeedMode = false; SearchDepth = 32; MaxInsertLen = 128; MaxLazyLen = 0; NiceLen = 0; break;
                    case ZstdLevel.Heavy: SearchDepth = 128; LazyDepth = 2; break;
                }
            }
            else
                switch (level)
                {
                    case ZstdLevel.Fast: DfShortMul = 0; break;
                    case ZstdLevel.Medium: SearchDepth = 16; RepCheckCount = 3; MaxLazyLen = 0; NiceLen = 0; break;
                    case ZstdLevel.Heavy: SearchDepth = 24; LazyDepth = 2; break;
                }
        }
        if (Tune != null) ApplyTuning();
        HashMul = 1;
        for (int i = 2; i <= MinMatch; i++) HashMul *= 256;
    }

    void ApplyTuning()
    {
        var t = Tune; Tune = null;
        if (t.MinMatch >= 0) MinMatch = t.MinMatch;
        if (t.SearchDepth >= 0) SearchDepth = t.SearchDepth;
        if (t.LazyDepth >= 0) LazyDepth = t.LazyDepth;
        if (t.LdmMinInput >= 0) LdmMinInput = t.LdmMinInput;
        if (t.MaxInsertLen >= 0) MaxInsertLen = t.MaxInsertLen;
        if (t.MaxLazyLen >= 0) MaxLazyLen = t.MaxLazyLen;
        if (t.NiceLen >= 0) NiceLen = t.NiceLen;
        SkipRunInsert = t.SkipRunInsert;
        if (t.RepChecks >= 0) RepCheckCount = t.RepChecks;
        if (t.SpeedMode >= 0) SpeedMode = t.SpeedMode == 1;
        if (t.DfShortMul >= 0) DfShortMul = t.DfShortMul * 4294967296L;
        if (t.Ldm >= 0) MaxStage = t.Ldm == 1 ? 7 : 6;
        if (MinMatch < 4 || MinMatch > 6 || SearchDepth < 1 || LazyDepth > 2 || (MaxInsertLen > 0 && MaxInsertLen < 8) || (NiceLen > 0 && NiceLen < 4))
            throw new ArgumentException("Invalid zstd compression settings.");
    }

    void WriteFrameHeader(bool singleSegment)
    {
        int fcsFlag;
        PutLE(4247762216L, 4);
        if (InLen < 256) fcsFlag = 0; else if (InLen < 65536 + 256) fcsFlag = 1; else fcsFlag = 2;
        int fhd = fcsFlag * 64;
        if (singleSegment) fhd += 32;
        PutByte(fhd);
        if (!singleSegment) PutByte((WindowLog - 10) * 8);
        switch (fcsFlag)
        {
            case 0: PutLE(InLen, 1); break;
            case 1: PutLE(InLen - 256, 2); break;
            case 2: PutLE(InLen, 4); break;
        }
    }

    void WriteBlocks(int blockMax)
    {
        if (InLen == 0) { PutBlockHeader(true, 0, 0); return; }
        int pos = 0;
        while (pos < InLen)
        {
            int size = InLen - pos;
            if (size > blockMax) size = blockMax;
            bool lastBlock = pos + size >= InLen;
            bool isRun = false;
            if (size >= 2)
                if (T[pos + 2] == T[pos + 1] && T[pos + size] == T[pos + 1] && T[pos + size / 2 + 1] == T[pos + 1])
                    isRun = AllEqual(T, pos + 1, size, T[pos + 1]);
            if (isRun)
            {
                PutBlockHeader(lastBlock, 1, size);
                OutTB.Append(T[pos + 1]);
            }
            else if (!TryCompressedBlock(pos, size, lastBlock))
            {
                PutBlockHeader(lastBlock, 0, size);
                OutTB.Append(T, pos + 1, size);
            }
            pos += size;
        }
    }

    static bool AllEqual(byte[] a, int start, int count, byte v) => a.AsSpan(start, count).IndexOfAnyExcept(v) < 0;

    void PutBlockHeader(bool lastBlock, int blockType, int size)
    {
        int header = size * 8 + blockType * 2;
        if (lastBlock) header += 1;
        PutLE(header, 3);
    }

    bool TryCompressedBlock(int start, int size, bool lastBlock)
    {
        if (MaxStage < 3) return false;
        BlockTB.Clear();
        FindSequences(start, size);
        Lit = new byte[LitTB.Length + 2];
        Buffer.BlockCopy(LitTB.ToArray(), 0, Lit, 1, LitTB.Length);
        if (!TryLiteralsHuffman())
        {
            BlockTB.Clear();
            WriteLiteralsRaw();
        }
        int litBytes = BlockTB.Length;
        WriteSequences();
        if (BlockTB.Length >= size) return false;
        Stats.Blocks++; Stats.Lits += LitCount; Stats.LitBytes += litBytes; Stats.Seqs += NbSeq;
        Stats.SeqBytes += BlockTB.Length - litBytes; Stats.SeqHdrBytes += SeqHdrEnd - litBytes;
        Stats.LitIdealBits += Entropy(Lit, 1, LitCount);
        if (NbSeq > 0) Stats.SeqIdealBits += SeqIdeal();
        PutBlockHeader(lastBlock, 2, BlockTB.Length);
        OutTB.Append(BlockTB.ToArray());
        Rep1 = PRep1; Rep2 = PRep2; Rep3 = PRep3;
        if (NbSeq > 0)
            for (int slot = 1; slot <= 3; slot++)
            {
                ComValid[slot] = true;
                ComRle[slot] = SlotMode[slot] == 1;
                ComTL[slot] = SlotTL[slot];
                ComMax[slot] = SlotMax[slot];
                for (int i = (slot - 1) * 64 + 1; i <= slot * 64; i++) ComNorm[i] = SlotNorm[i];
            }
        return true;
    }

    void FindSequences(int start, int size)
    {
        LitTB.Clear();
        NbSeq = 0;
        LitCount = 0;
        SeqAnchor = start;
        PRep1 = (int)Rep1; PRep2 = (int)Rep2; PRep3 = (int)Rep3;
        if (MaxStage >= 7 && InLen > LdmMinInput) ParseWithLdm(start, start + size);
        else if (DoubleFast) ParseDoubleFast(start, start + size);
        else ParseLazy(start, start + size);
        if (start + size > SeqAnchor)
        {
            LitTB.Append(T, SeqAnchor + 1, start + size - SeqAnchor);
            LitCount += start + size - SeqAnchor;
        }
    }

    bool Eq(int a, int b, int n) => T.AsSpan(a, n).SequenceEqual(T.AsSpan(b, n));

    /// <summary>Extension ladder past 16 : 64-byte bulk, 256-byte bulk after a 64 hit, 64-byte bulk, then per byte.</summary>
    int Ladder(int cand, int q, int l, int maxLen)
    {
        if (l + 64 <= maxLen)
            if (Eq(cand + l + 1, q + l + 1, 64))
            {
                l += 64;
                while (l + 256 <= maxLen) { if (Eq(cand + l + 1, q + l + 1, 256)) l += 256; else break; }
                while (l + 64 <= maxLen) { if (Eq(cand + l + 1, q + l + 1, 64)) l += 64; else break; }
            }
        while (T[cand + l + 1] == T[q + l + 1] && l < maxLen) { l++; Stats.Bytes++; }
        return l;
    }

    void ParseLazy(int Pos, int BlockEnd)
    {
        int C, Q, Cand, MaxLen, L, G, B, R = 0, SDepth, BestLen = 0, BestOff = 0, BestGain = 0, Depth = 0, LL, OV, RepCode, RepChecks, Lim, MinCand, Reach, Last;
        byte QChar;
        bool Lazy = false, Emit;
        Reach = WindowSize;
        if (Reach > 999999) Reach = 999999;
        RepChecks = RepCheckCount;
        while (Pos + 4 <= BlockEnd)
        {
            Stats.Positions++;
            Q = Lazy ? Pos + 1 : Pos;

            if (NextIns <= Q)
            {
                Last = Q;
                if (Last > InLen - MinMatch) Last = InLen - MinMatch;
                if (NextIns <= Last)
                {
                    if (InsVPos != NextIns)
                    {
                        InsV = 0;
                        for (L = MinMatch; L >= 1; L--) { C = T[NextIns + L]; InsV = InsV * 256 + C; }
                    }
                    do
                    {
                        Chain[NextIns % 1000000 + 1] = Head[InsV % 524287 + 1];
                        Head[InsV % 524287 + 1] = NextIns + 1 + PosBase;
                        InsV = InsV / 256 + T[NextIns + MinMatch + 1] * HashMul;
                        NextIns++;
                        Stats.Inserts++;
                    } while (!(NextIns > Last));
                    InsVPos = NextIns;
                }
                NextIns = Q + 1;
            }

            FBLen = 0;
            FBGain = 0;
            MaxLen = BlockEnd - Q;
            if (MaxLen >= 4)
            {
                Lim = MaxLen;
                if (Lim > 16) Lim = 16;
                for (int RepNo = 1; RepNo <= RepChecks; RepNo++)
                {
                    switch (RepNo) { case 1: R = PRep1; break; case 2: R = PRep2; break; case 3: R = PRep3; break; }
                    if (R <= Q && R <= WindowSize)
                    {
                        Cand = Q - R;
                        L = 0;
                        while (T[Cand + L + 1] == T[Q + L + 1] && L < Lim) { L++; Stats.Bytes++; }
                        if (L == 16) L = Ladder(Cand, Q, L, MaxLen);
                        if (L >= 4)
                        {
                            G = L * 4 - 1;
                            if (G > FBGain) { FBLen = L; FBOff = R; FBGain = G; }
                        }
                    }
                }

                if (FBLen < MaxLen && !(NiceLen > 0 && FBLen >= NiceLen))
                {
                    Cand = Chain[Q % 1000000 + 1] - 1 - PosBase;
                    SDepth = SearchDepth;
                    if (SpeedMode && Lazy && BestLen >= 8) SDepth = (SearchDepth + 3) / 4;
                    MinCand = Q - Reach;
                    if (MinCand < 0) MinCand = 0;
                    QChar = T[Q + FBLen + 1];
                    while (Cand >= MinCand && SDepth > 0)
                    {
                        Stats.Candidates++;
                        if (T[Cand + FBLen + 1] == QChar)
                        {
                            L = 0;
                            if (FBLen >= 16)
                                L = Eq(Cand + 1, Q + 1, FBLen) ? FBLen + 1 : -1;
                            if (L >= 0)
                            {
                                while (T[Cand + L + 1] == T[Q + L + 1] && L < Lim) { L++; Stats.Bytes++; }
                                if (L >= 16) L = Ladder(Cand, Q, L, MaxLen);
                            }
                            if (L >= MinMatch)
                            {
                                B = Q - Cand + 3;
                                if (B <= 1024) G = L * 4 - HBTbl[B];
                                else if (B <= 1048576) G = L * 4 - 10 - HBTbl[B / 1024];
                                else G = L * 4 - 20 - HBTbl[B / 1048576];
                                if (G > FBGain)
                                {
                                    FBLen = L;
                                    FBOff = Q - Cand;
                                    FBGain = G;
                                    QChar = T[Q + FBLen + 1];
                                    if (L == MaxLen || (NiceLen > 0 && L >= NiceLen)) SDepth = 0;
                                }
                            }
                        }
                        Cand = Chain[Cand % 1000000 + 1] - 1 - PosBase;
                        SDepth--;
                    }
                }
            }

            Emit = false;
            if (!Lazy)
            {
                if (FBLen == 0)
                {
                    if (SpeedMode)
                    {
                        Pos += 1 + (Pos - SeqAnchor) / 128;
                        if (SkipRunInsert)
                            if (NextIns < Pos) NextIns = Pos;
                    }
                    else Pos += 1;
                }
                else
                {
                    BestLen = FBLen; BestOff = FBOff; BestGain = FBGain;
                    Depth = 1;
                    if (LazyDepth >= 1 && Pos + 5 <= BlockEnd && !(MaxLazyLen > 0 && BestLen >= MaxLazyLen)) Lazy = true;
                    else Emit = true;
                }
            }
            else if (FBGain > BestGain + 1 + 3 * Depth)
            {
                Pos += 1;
                BestLen = FBLen; BestOff = FBOff; BestGain = FBGain;
                Depth += 1;
                if (Depth > LazyDepth || Pos + 5 > BlockEnd || (MaxLazyLen > 0 && BestLen >= MaxLazyLen)) Emit = true;
            }
            else Emit = true;

            if (Emit)
            {
                LL = Pos - SeqAnchor;
                if (LL > 0) { LitTB.Append(T, SeqAnchor + 1, LL); LitCount += LL; }
                OV = BestOff + 3;
                if (MaxStage >= 5)
                {
                    if (LL > 0)
                    {
                        if (BestOff == PRep1) OV = 1; else if (BestOff == PRep2) OV = 2; else if (BestOff == PRep3) OV = 3;
                    }
                    else
                    {
                        if (BestOff == PRep2) OV = 1; else if (BestOff == PRep3) OV = 2; else if (BestOff == PRep1 - 1) OV = 3;
                    }
                }
                if (OV > 3) { PRep3 = PRep2; PRep2 = PRep1; PRep1 = BestOff; }
                else
                {
                    RepCode = OV;
                    if (LL == 0) RepCode += 1;
                    switch (RepCode)
                    {
                        case 2: PRep2 = PRep1; PRep1 = BestOff; break;
                        case 3: case 4: PRep3 = PRep2; PRep2 = PRep1; PRep1 = BestOff; break;
                    }
                }
                NbSeq++;
                SeqLL[NbSeq] = LL; SeqML[NbSeq] = BestLen; SeqOfv[NbSeq] = OV;
                SeqAnchor = Pos + BestLen;
                Pos += BestLen;
                Lazy = false;
                if (MaxInsertLen > 0 && BestLen > MaxInsertLen && NextIns < Pos - MaxInsertLen / 4)
                    NextIns = Pos - MaxInsertLen / 4;
            }
        }
    }

    void ParseDoubleFast(int Pos, int BlockEnd)
    {
        long VS = 0, VL = 0;
        int HS, HL, C, P, CandL, CandS, Cn = 0, S = 0, MinL = 0, MaxLen, L, ML, MStart = 0, Off = 0, NewPos, LL, OV, RepCode, VPos, Lim;
        bool Valid, Same;
        VPos = -2;
        while (Pos + 8 <= BlockEnd)
        {
            Stats.Positions++;
            if (VPos == Pos - 1)
            {
                C = T[Pos + 8];
                VS = VS / 256 + (VL % 256) * 16777216L;
                VL = VL / 256 + C * 16777216L;
            }
            else
            {
                VS = 0;
                for (int k = 4; k >= 1; k--) { C = T[Pos + k]; VS = VS * 256 + C; }
                VL = 0;
                for (int k = 8; k >= 5; k--) { C = T[Pos + k]; VL = VL * 256 + C; }
            }
            VPos = Pos;
            HS = (int)(((((VS + (VL % 256) * DfShortMul) % 4294967291L) * 506832829) % 4294967296L) / 8192);
            HL = (int)((((VL * 1640531527) % 4294967296L + VS * 2654435) % 4294967296L) / 8192);
            CandL = DfLong[HL + 1] - 1 - PosBase;
            CandS = DfShort[HS + 1] - 1 - PosBase;
            DfLong[HL + 1] = Pos + 1 + PosBase;
            DfShort[HS + 1] = Pos + 1 + PosBase;
            Stats.Inserts += 2;

            ML = 0;
            for (int Kind = 1; Kind <= 3; Kind++)
                if (ML == 0)
                {
                    Valid = false;
                    switch (Kind)
                    {
                        case 1: S = Pos + 1; Cn = S - PRep1; MinL = 4; Valid = Cn >= 0; break;
                        case 2: S = Pos; Cn = CandL; MinL = 8; if (Cn >= 0) Valid = Pos - Cn <= WindowSize; break;
                        case 3: S = Pos; Cn = CandS; MinL = 5; if (Cn >= 0 && Cn != CandL) Valid = Pos - Cn <= WindowSize; break;
                    }
                    if (Valid)
                    {
                        Stats.Candidates++;
                        MaxLen = BlockEnd - S;
                        Lim = MaxLen;
                        if (Lim > 16) Lim = 16;
                        L = 0;
                        while (T[Cn + L + 1] == T[S + L + 1] && L < Lim) { L++; Stats.Bytes++; }
                        if (L == 16) L = Ladder(Cn, S, L, MaxLen);
                        if (L >= MinL) { ML = L; MStart = S; Off = S - Cn; }
                    }
                }

            if (ML == 0) Pos += 1 + (Pos - SeqAnchor) / 128;
            else
            {
                Same = true;
                while (Same && MStart > SeqAnchor && MStart - Off > 0)
                    if (T[MStart] == T[MStart - Off]) { MStart--; ML++; }
                    else Same = false;

                LL = MStart - SeqAnchor;
                if (LL > 0) { LitTB.Append(T, SeqAnchor + 1, LL); LitCount += LL; }
                OV = Off + 3;
                if (LL > 0)
                {
                    if (Off == PRep1) OV = 1; else if (Off == PRep2) OV = 2; else if (Off == PRep3) OV = 3;
                }
                else
                {
                    if (Off == PRep2) OV = 1; else if (Off == PRep3) OV = 2; else if (Off == PRep1 - 1) OV = 3;
                }
                if (OV > 3) { PRep3 = PRep2; PRep2 = PRep1; PRep1 = Off; }
                else
                {
                    RepCode = OV;
                    if (LL == 0) RepCode += 1;
                    switch (RepCode)
                    {
                        case 2: PRep2 = PRep1; PRep1 = Off; break;
                        case 3: case 4: PRep3 = PRep2; PRep2 = PRep1; PRep1 = Off; break;
                    }
                }
                NbSeq++;
                SeqLL[NbSeq] = LL; SeqML[NbSeq] = ML; SeqOfv[NbSeq] = OV;
                NewPos = MStart + ML;
                SeqAnchor = NewPos;

                for (int K = 1; K <= 2; K++)
                {
                    P = K == 1 ? MStart + 2 : NewPos - 2;
                    if (P > Pos && P + 8 <= InLen)
                    {
                        VS = 0;
                        for (int j = 4; j >= 1; j--) { C = T[P + j]; VS = VS * 256 + C; }
                        VL = 0;
                        for (int j = 8; j >= 5; j--) { C = T[P + j]; VL = VL * 256 + C; }
                        HS = (int)(((((VS + (VL % 256) * DfShortMul) % 4294967291L) * 506832829) % 4294967296L) / 8192);
                        HL = (int)((((VL * 1640531527) % 4294967296L + VS * 2654435) % 4294967296L) / 8192);
                        DfLong[HL + 1] = P + 1 + PosBase;
                        DfShort[HS + 1] = P + 1 + PosBase;
                        Stats.Inserts += 2;
                    }
                }
                VPos = -2;
                Pos = NewPos;
            }
        }
    }

    void ParseWithLdm(int start, int blockEnd)
    {
        FindLdmMatches(start, blockEnd);
        int pos = start;
        for (int i = 1; i <= LdmCount; i++)
        {
            if (DoubleFast) ParseDoubleFast(pos, LdmStart[i]); else ParseLazy(pos, LdmStart[i]);
            EmitSequence(LdmStart[i], LdmLen[i], LdmOff[i]);
            pos = LdmStart[i] + LdmLen[i];
            if (NextIns < pos) NextIns = pos;
        }
        if (DoubleFast) ParseDoubleFast(pos, blockEnd); else ParseLazy(pos, blockEnd);
    }

    void FindLdmMatches(int Start, int BlockEnd)
    {
        long H = 0;
        int C, P, S, PEnd, Bucket, Tag, Slot, Cand, L, Back, LowLimit, BestLen, BestBack = 0, BestCand = 0;
        bool Same, NeedInit;
        LdmCount = 0;
        LowLimit = Start;
        PEnd = BlockEnd - 1;
        if (PEnd > InLen - 1) PEnd = InLen - 1;
        P = Start + 31;
        NeedInit = true;
        while (P <= PEnd)
        {
            if (NeedInit)
            {
                H = 0;
                for (int k = P - 30; k <= P + 1; k++) { C = T[k]; H = (H * 2 + Gear[C + 1]) % 4294967296L; }
                NeedInit = false;
            }
            if (H < 268435456)
            {
                S = P - 31;
                Bucket = (int)(H % 131072);
                Tag = (int)((H / 131072) % 2048);
                BestLen = 0;
                for (int k = 0; k <= 3; k++)
                {
                    Slot = Bucket * 4 + k + 1;
                    Cand = LdmPos[Slot] - 1 - PosBase;
                    if (Cand >= 0 && LdmTag[Slot] == Tag)
                        if (S - Cand <= WindowSize && Cand < S)
                            if (Eq(Cand + 1, S + 1, 32))
                            {
                                L = 32;
                                while (S + L + 256 <= BlockEnd) { if (Eq(Cand + L + 1, S + L + 1, 256)) L += 256; else break; }
                                while (S + L + 64 <= BlockEnd) { if (Eq(Cand + L + 1, S + L + 1, 64)) L += 64; else break; }
                                while (T[Cand + L + 1] == T[S + L + 1] && S + L < BlockEnd) L++;
                                Back = 0;
                                Same = true;
                                while (Same && S - Back > LowLimit && Cand - Back > 0)
                                    if (T[Cand - Back] == T[S - Back]) Back++; else Same = false;
                                if (L + Back >= 64 && L + Back > BestLen) { BestLen = L + Back; BestBack = Back; BestCand = Cand; }
                            }
                }
                Slot = Bucket * 4 + LdmNext[Bucket + 1] + 1;
                LdmPos[Slot] = S + 1 + PosBase;
                LdmTag[Slot] = Tag;
                LdmNext[Bucket + 1] = (LdmNext[Bucket + 1] + 1) % 4;
                if (BestLen > 0)
                {
                    LdmCount++;
                    LdmStart[LdmCount] = S - BestBack;
                    LdmLen[LdmCount] = BestLen;
                    LdmOff[LdmCount] = S - BestCand;
                    LowLimit = S - BestBack + BestLen;
                    P = LowLimit + 31;
                    NeedInit = true;
                }
            }
            if (!NeedInit)
                do
                {
                    P++;
                    H = (H * 2 + Gear[T[P + 1] + 1]) % 4294967296L;
                } while (!(H < 268435456 || P > PEnd));
        }
    }

    void EmitSequence(int pos, int ml, int off)
    {
        int ll = pos - SeqAnchor, ov, repCode;
        if (ll > 0) { LitTB.Append(T, SeqAnchor + 1, ll); LitCount += ll; }
        ov = off + 3;
        if (MaxStage >= 5)
        {
            if (ll > 0) { if (off == PRep1) ov = 1; else if (off == PRep2) ov = 2; else if (off == PRep3) ov = 3; }
            else { if (off == PRep2) ov = 1; else if (off == PRep3) ov = 2; else if (off == PRep1 - 1) ov = 3; }
        }
        if (ov > 3) { PRep3 = PRep2; PRep2 = PRep1; PRep1 = off; }
        else
        {
            repCode = ov;
            if (ll == 0) repCode += 1;
            switch (repCode)
            {
                case 2: PRep2 = PRep1; PRep1 = off; break;
                case 3: case 4: PRep3 = PRep2; PRep2 = PRep1; PRep1 = off; break;
            }
        }
        NbSeq++;
        SeqLL[NbSeq] = ll; SeqML[NbSeq] = ml; SeqOfv[NbSeq] = ov;
        SeqAnchor = pos + ml;
    }

    void WriteLiteralsRaw()
    {
        int lType = 0;
        if (MaxStage >= 4)
            if (LitCount > 1)
                if (AllEqual(Lit, 1, LitCount, Lit[1])) lType = 1;
        if (LitCount < 32) PutBlockByte(LitCount * 8 + lType);
        else if (LitCount < 4096)
        {
            PutBlockByte((LitCount % 16) * 16 + 4 + lType);
            PutBlockByte(LitCount / 16);
        }
        else
        {
            PutBlockByte((LitCount % 16) * 16 + 12 + lType);
            PutBlockByte((LitCount / 16) % 256);
            PutBlockByte(LitCount / 4096);
        }
        if (lType == 1) BlockTB.Append(Lit[1]);
        else BlockTB.Append(Lit, 1, LitCount);
    }

    // ---------------------------------------------------------------------------------------- Huffman literals
    bool TryLiteralsHuffman()
    {
        long h;
        byte[] treeText;
        var streamText = new byte[5][];
        int maxSym = 0, distinct = 0, segment, compSize, sizeFormat, headerBytes = 0, nBits = 0, rawHeader, start = 0;
        var rankCount = new int[13];
        var rankNext = new int[13];
        if (MaxStage < 4 || LitCount < 64) return false;
        Array.Clear(LitHist);
        for (int i = 1; i <= LitCount; i++) LitHist[Lit[i] + 1]++;
        for (int s = 0; s <= 255; s++)
            if (LitHist[s + 1] > 0) { distinct++; maxSym = s; }
        if (distinct < 2) return false;

        BuildHuffmanLengths(maxSym);
        for (int s = 0; s <= maxSym; s++)
            HufWeight[s + 1] = HufLen[s + 1] > 0 ? HufMax + 1 - HufLen[s + 1] : 0;
        treeText = BuildTreeDescription(maxSym);
        if (treeText.Length == 0) return false;

        for (int s = 0; s <= maxSym; s++)
            if (HufWeight[s + 1] > 0) rankCount[HufWeight[s + 1]]++;
        for (int w = 1; w <= HufMax; w++)
        {
            rankNext[w] = start;
            start += (int)(rankCount[w] * Pow2B[w]);
        }
        for (int s = 0; s <= maxSym; s++)
        {
            int w = HufWeight[s + 1];
            if (w > 0)
            {
                HufCode[s + 1] = (int)(rankNext[w] / Pow2B[w]);
                rankNext[w] += (int)Pow2B[w];
            }
        }

        if (LitCount < 256)
        {
            streamText[1] = EncodeHufStream(1, LitCount);
            compSize = treeText.Length + streamText[1].Length;
            sizeFormat = 0;
        }
        else
        {
            segment = (LitCount + 3) / 4;
            streamText[1] = EncodeHufStream(1, segment);
            streamText[2] = EncodeHufStream(segment + 1, 2 * segment);
            streamText[3] = EncodeHufStream(2 * segment + 1, 3 * segment);
            streamText[4] = EncodeHufStream(3 * segment + 1, LitCount);
            compSize = treeText.Length + 6;
            for (int i = 1; i <= 4; i++) compSize += streamText[i].Length;
            sizeFormat = 1;
        }
        if (LitCount > 1023 || compSize > 1023) sizeFormat = 2;
        if (LitCount > 16383 || compSize > 16383) sizeFormat = 3;
        if (sizeFormat == 0)
            if (compSize > 1023) return false;
        switch (sizeFormat)
        {
            case 0: case 1: headerBytes = 3; nBits = 10; break;
            case 2: headerBytes = 4; nBits = 14; break;
            case 3: headerBytes = 5; nBits = 18; break;
        }
        rawHeader = 1;
        if (LitCount >= 32) rawHeader = 2;
        if (LitCount >= 4096) rawHeader = 3;
        if (headerBytes + compSize >= rawHeader + LitCount) return false;

        BlockTB.Clear();
        h = 2 + sizeFormat * 4 + LitCount * 16L + compSize * Pow2B[nBits + 5];
        for (int i = 1; i <= headerBytes; i++) { PutBlockByte((int)(h % 256)); h /= 256; }
        BlockTB.Append(treeText);
        if (sizeFormat == 0) BlockTB.Append(streamText[1]);
        else
        {
            for (int i = 1; i <= 3; i++)
            {
                PutBlockByte(streamText[i].Length % 256);
                PutBlockByte(streamText[i].Length / 256);
            }
            for (int i = 1; i <= 4; i++) BlockTB.Append(streamText[i]);
        }
        return true;
    }

    byte[] EncodeHufStream(int firstIdx, int lastIdx)
    {
        BlockTB.Clear();
        BwAcc = 0;
        BwCount = 0;
        for (int i = lastIdx; i >= firstIdx; i--)
        {
            int c = Lit[i];
            BwAcc += HufCode[c + 1] * Pow2B[BwCount + 1];
            BwCount += HufLen[c + 1];
            while (BwCount >= 16) { BlockTB.Append((byte)(BwAcc % 65536 % 256)); BlockTB.Append((byte)(BwAcc % 65536 / 256)); BwAcc /= 65536; BwCount -= 16; }
            if (BwCount >= 8) { BlockTB.Append((byte)(BwAcc % 256)); BwAcc /= 256; BwCount -= 8; }
        }
        BitCloseStream();
        return BlockTB.ToArray();
    }

    void BuildHuffmanLengths(int maxSym)
    {
        long k = 0, target;
        int nLeaves = 0, nNodes, a, b, p, d, best, len;
        Array.Clear(HufLen);
        for (int s = 0; s <= maxSym; s++)
            if (LitHist[s + 1] > 0)
            {
                nLeaves++;
                LeafSym[nLeaves] = s;
                NodeW[nLeaves] = LitHist[s + 1];
                NodeParent[nLeaves] = 0;
                NodeAlive[nLeaves] = true;
            }
        nNodes = nLeaves;
        while (nNodes < 2 * nLeaves - 1)
        {
            a = 0; b = 0;
            for (int n = 1; n <= nNodes; n++)
                if (NodeAlive[n])
                {
                    if (a == 0) a = n;
                    else if (NodeW[n] < NodeW[a]) { b = a; a = n; }
                    else if (b == 0) b = n;
                    else if (NodeW[n] < NodeW[b]) b = n;
                }
            nNodes++;
            NodeW[nNodes] = NodeW[a] + NodeW[b];
            NodeParent[nNodes] = 0;
            NodeAlive[nNodes] = true;
            NodeParent[a] = nNodes;
            NodeParent[b] = nNodes;
            NodeAlive[a] = false;
            NodeAlive[b] = false;
        }
        HufMax = 0;
        for (int n = 1; n <= nLeaves; n++)
        {
            d = 0; p = n;
            while (NodeParent[p] != 0) { p = NodeParent[p]; d++; }
            HufLen[LeafSym[n] + 1] = d;
            if (d > HufMax) HufMax = d;
        }
        if (HufMax <= 11) return;

        target = Pow2B[12];
        for (int s = 0; s <= maxSym; s++)
            if (HufLen[s + 1] > 0)
            {
                if (HufLen[s + 1] > 11) HufLen[s + 1] = 11;
                k += Pow2B[12 - HufLen[s + 1]];
            }
        while (k > target)
        {
            best = -1;
            for (int s = 0; s <= maxSym; s++)
            {
                len = HufLen[s + 1];
                if (len > 0 && len < 11)
                {
                    if (best == -1) best = s;
                    else if (len > HufLen[best + 1]) best = s;
                }
            }
            k -= Pow2B[11 - HufLen[best + 1]];
            HufLen[best + 1]++;
        }
        while (k < target)
        {
            best = -1;
            for (int s = 0; s <= maxSym; s++)
            {
                len = HufLen[s + 1];
                if (len > 1)
                    if (k + Pow2B[12 - len] <= target)
                    {
                        if (best == -1) best = s;
                        else if (len > HufLen[best + 1]) best = s;
                    }
            }
            k += Pow2B[12 - HufLen[best + 1]];
            HufLen[best + 1]--;
        }
        HufMax = 0;
        for (int s = 0; s <= maxSym; s++)
            if (HufLen[s + 1] > HufMax) HufMax = HufLen[s + 1];
    }

    byte[] BuildTreeDescription(int maxSym)
    {
        byte[] direct = Array.Empty<byte>(), fse;
        if (maxSym <= 128)
        {
            BlockTB.Clear();
            PutBlockByte(127 + maxSym);
            int i = 1;
            while (i <= maxSym)
            {
                int w2 = 0;
                if (i < maxSym) w2 = HufWeight[i + 1];
                PutBlockByte(HufWeight[i] * 16 + w2);
                i += 2;
            }
            direct = BlockTB.ToArray();
        }
        fse = BuildWeightsFse(maxSym);
        if (fse.Length == 0) return direct;
        if (direct.Length == 0) return fse;
        if (fse.Length < direct.Length) return fse;
        return direct;
    }

    byte[] BuildWeightsFse(int n)
    {
        int s1, s2, i, maxW = 0, distinct = 0;
        if (n < 2) return Array.Empty<byte>();
        Array.Clear(HistCount);
        for (i = 1; i <= n; i++)
        {
            HistCount[HufWeight[i] + 1]++;
            if (HufWeight[i] > maxW) maxW = HufWeight[i];
        }
        for (i = 0; i <= maxW; i++)
            if (HistCount[i + 1] > 0) distinct++;
        if (distinct < 2) return Array.Empty<byte>();
        NormalizeCounts(maxW, 6, n);
        BuildCTable(4, maxW, 6);
        BlockTB.Clear();
        BwAcc = 0;
        BwCount = 0;
        WriteNCount(maxW, 6);
        if (n % 2 == 1)
        {
            s1 = FseInitState(4, HufWeight[n]);
            s2 = FseInitState(4, HufWeight[n - 1]);
            FseEncode(4, ref s1, HufWeight[n - 2]);
            i = n - 3;
        }
        else
        {
            s2 = FseInitState(4, HufWeight[n]);
            s1 = FseInitState(4, HufWeight[n - 1]);
            i = n - 2;
        }
        while (i > 0)
        {
            FseEncode(4, ref s2, HufWeight[i]);
            FseEncode(4, ref s1, HufWeight[i - 1]);
            i -= 2;
        }
        FseFlushState(4, s2);
        FseFlushState(4, s1);
        BitCloseStream();
        if (BlockTB.Length >= 128) return Array.Empty<byte>();
        var body = BlockTB.ToArray();
        var r = new byte[body.Length + 1];
        r[0] = (byte)body.Length;
        Buffer.BlockCopy(body, 0, r, 1, body.Length);
        return r;
    }

    // ---------------------------------------------------------------------------------------- Sequences
    void WriteSequences()
    {
        int v, n, idx, nb, stateLL = 0, stateOF = 0, stateML = 0;
        bool rleLL, rleOF, rleML;
        if (NbSeq < 128) PutBlockByte(NbSeq);
        else if (NbSeq < 32512) { PutBlockByte(NbSeq / 256 + 128); PutBlockByte(NbSeq % 256); }
        else { PutBlockByte(255); PutBlockByte((NbSeq - 32512) % 256); PutBlockByte((NbSeq - 32512) / 256); }
        if (NbSeq == 0) return;

        Array.Clear(SeqHist);
        for (n = 1; n <= NbSeq; n++)
        {
            v = SeqLL[n];
            if (v < 64) SeqLLCode[n] = LLCodeTbl[v + 1];
            else if (v <= 1024) SeqLLCode[n] = HBTbl[v] + 19;
            else SeqLLCode[n] = HBTbl[v / 1024] + 29;
            v = SeqML[n] - 3;
            if (v < 128) SeqMLCode[n] = MLCodeTbl[v + 1];
            else if (v <= 1024) SeqMLCode[n] = HBTbl[v] + 36;
            else SeqMLCode[n] = HBTbl[v / 1024] + 46;
            v = SeqOfv[n];
            if (v <= 1024) SeqOFCode[n] = HBTbl[v];
            else if (v <= 1048576) SeqOFCode[n] = HBTbl[v / 1024] + 10;
            else SeqOFCode[n] = HBTbl[v / 1048576] + 20;
            SeqHist[SeqLLCode[n] + 1]++;
            SeqHist[SeqOFCode[n] + 65]++;
            SeqHist[SeqMLCode[n] + 129]++;
        }

        for (int slot = 1; slot <= 3; slot++) ChooseTable(slot);
        PutBlockByte(SlotMode[1] * 64 + SlotMode[2] * 16 + SlotMode[3] * 4);
        for (int slot = 1; slot <= 3; slot++)
            switch (SlotMode[slot])
            {
                case 1: PutBlockByte(SlotRleSym[slot]); break;
                case 2: LoadSlotNorm(slot); BwAcc = 0; BwCount = 0; WriteNCount(SlotMax[slot], SlotTL[slot]); break;
            }
        SeqHdrEnd = BlockTB.Length;
        rleLL = SlotMode[1] == 1;
        rleOF = SlotMode[2] == 1;
        rleML = SlotMode[3] == 1;

        BwAcc = 0;
        BwCount = 0;
        n = NbSeq;
        if (!rleML) stateML = FseInitState(3, SeqMLCode[n]);
        if (!rleOF) stateOF = FseInitState(2, SeqOFCode[n]);
        if (!rleLL) stateLL = FseInitState(1, SeqLLCode[n]);
        AddBits(SeqLL[n], LLBits[SeqLLCode[n] + 1]);
        AddBits(SeqML[n] - 3, MLBits[SeqMLCode[n] + 1]);
        AddBits(SeqOfv[n], SeqOFCode[n]);
        for (n = NbSeq - 1; n >= 1; n--)
        {
            if (!rleOF)
            {
                idx = 64 + SeqOFCode[n] + 1;
                nb = (stateOF + DeltaNbBits[idx]) / 65536;
                BwAcc += (stateOF % Pow2B[nb + 1]) * Pow2B[BwCount + 1];
                BwCount += nb;
                stateOF = CState[512 + (int)(stateOF / Pow2B[nb + 1]) + DeltaFindState[idx] + 1];
            }
            if (!rleML)
            {
                idx = 128 + SeqMLCode[n] + 1;
                nb = (stateML + DeltaNbBits[idx]) / 65536;
                BwAcc += (stateML % Pow2B[nb + 1]) * Pow2B[BwCount + 1];
                BwCount += nb;
                stateML = CState[1024 + (int)(stateML / Pow2B[nb + 1]) + DeltaFindState[idx] + 1];
            }
            if (!rleLL)
            {
                idx = SeqLLCode[n] + 1;
                nb = (stateLL + DeltaNbBits[idx]) / 65536;
                BwAcc += (stateLL % Pow2B[nb + 1]) * Pow2B[BwCount + 1];
                BwCount += nb;
                stateLL = CState[(int)(stateLL / Pow2B[nb + 1]) + DeltaFindState[idx] + 1];
            }
            FlushBits();
            nb = LLBits[SeqLLCode[n] + 1];
            BwAcc += (SeqLL[n] % Pow2B[nb + 1]) * Pow2B[BwCount + 1];
            BwCount += nb;
            nb = MLBits[SeqMLCode[n] + 1];
            BwAcc += ((SeqML[n] - 3) % Pow2B[nb + 1]) * Pow2B[BwCount + 1];
            BwCount += nb;
            nb = SeqOFCode[n];
            BwAcc += (SeqOfv[n] - Pow2B[nb + 1]) * Pow2B[BwCount + 1];
            BwCount += nb;
            FlushBits();
        }
        if (!rleML) FseFlushState(3, stateML);
        if (!rleOF) FseFlushState(2, stateOF);
        if (!rleLL) FseFlushState(1, stateLL);
        BitCloseStream();
    }

    int SeqHdrEnd;
    static double Entropy(byte[] a, int start, int count)
    {
        var h = new int[256];
        for (int i = start; i < start + count; i++) h[a[i]]++;
        double bits = 0;
        foreach (var c in h) if (c > 0) bits -= c * Math.Log2((double)c / count);
        return bits;
    }
    double SeqIdeal()
    {
        double bits = 0;
        for (int slot = 0; slot < 3; slot++)
            for (int c = 0; c < 64; c++) { int k = SeqHist[slot * 64 + c + 1]; if (k > 0) bits -= k * Math.Log2((double)k / NbSeq); }
        for (int n = 1; n <= NbSeq; n++) bits += LLBits[SeqLLCode[n] + 1] + MLBits[SeqMLCode[n] + 1] + SeqOFCode[n];
        return bits;
    }

    void FlushBits()
    {
        while (BwCount >= 16) { BlockTB.Append((byte)(BwAcc % 256)); BlockTB.Append((byte)(BwAcc / 256 % 256)); BwAcc /= 65536; BwCount -= 16; }
        if (BwCount >= 8) { BlockTB.Append((byte)(BwAcc % 256)); BwAcc /= 256; BwCount -= 8; }
    }

    void ChooseTable(int slot)
    {
        long costPre, costRep, costNew;
        int maxLog, maxUsed = 0, distinct = 0, newTL, norm, l0;
        var preNorm = new int[65];
        var newNorm = new int[65];
        int b = (slot - 1) * 64;
        for (int s = 0; s <= 63; s++)
        {
            HistCount[s + 1] = SeqHist[b + s + 1];
            if (HistCount[s + 1] > 0) { maxUsed = s; distinct++; }
        }
        SetPredefinedNorm(slot, out int preMax, out int preTL);
        for (int s = 0; s <= preMax; s++) preNorm[s + 1] = NormCount[s + 1];
        if (MaxStage < 5) { SetSlot(slot, 0, preMax, preTL, preNorm, 0); return; }
        if (distinct == 1) { SetSlot(slot, 1, maxUsed, 0, preNorm, maxUsed); return; }
        costPre = -1;
        if (maxUsed <= preMax)
        {
            costPre = 0;
            for (int s = 0; s <= maxUsed; s++)
                if (HistCount[s + 1] > 0)
                {
                    norm = preNorm[s + 1];
                    if (norm < 0) norm = 1;
                    costPre += (long)HistCount[s + 1] * (preTL * 256 - Log2Q8[norm]);
                }
        }

        costRep = -1;
        if (ComValid[slot] && !ComRle[slot] && maxUsed <= ComMax[slot])
        {
            costRep = 0;
            for (int s = 0; s <= maxUsed; s++)
                if (HistCount[s + 1] > 0)
                {
                    norm = ComNorm[b + s + 1];
                    if (norm < 0) norm = 1;
                    if (norm == 0) costRep = -1;
                    if (costRep >= 0) costRep += (long)HistCount[s + 1] * (ComTL[slot] * 256 - Log2Q8[norm]);
                }
        }

        maxLog = slot == 2 ? 8 : 9;
        newTL = maxLog;
        if (HighBit(NbSeq - 1) - 2 < newTL) newTL = HighBit(NbSeq - 1) - 2;
        if (HighBit(maxUsed) + 2 > newTL) newTL = HighBit(maxUsed) + 2;
        if (newTL < 5) newTL = 5;
        if (newTL > maxLog) newTL = maxLog;
        NormalizeCounts(maxUsed, newTL, NbSeq);
        costNew = 0;
        for (int s = 0; s <= maxUsed; s++)
        {
            newNorm[s + 1] = NormCount[s + 1];
            if (HistCount[s + 1] > 0)
            {
                norm = NormCount[s + 1];
                if (norm < 0) norm = 1;
                costNew += (long)HistCount[s + 1] * (newTL * 256 - Log2Q8[norm]);
            }
        }
        l0 = BlockTB.Length;
        BwAcc = 0;
        BwCount = 0;
        WriteNCount(maxUsed, newTL);
        costNew += (long)(BlockTB.Length - l0) * 8 * 256;
        BlockTB.Truncate(l0);

        if (costPre >= 0 && (costRep < 0 || costPre <= costRep) && costPre <= costNew)
            SetSlot(slot, 0, preMax, preTL, preNorm, 0);
        else if (costRep >= 0 && costRep <= costNew)
        {
            for (int s = 0; s <= ComMax[slot]; s++) newNorm[s + 1] = ComNorm[b + s + 1];
            SetSlot(slot, 3, ComMax[slot], ComTL[slot], newNorm, 0);
        }
        else SetSlot(slot, 2, maxUsed, newTL, newNorm, 0);
    }

    void SetSlot(int slot, int mode, int maxSymbol, int tableLog, int[] norm, int rleSymbol)
    {
        int b = (slot - 1) * 64;
        SlotMode[slot] = mode;
        SlotMax[slot] = maxSymbol;
        SlotTL[slot] = tableLog;
        SlotRleSym[slot] = rleSymbol;
        for (int s = 0; s <= 63; s++)
            SlotNorm[b + s + 1] = s <= maxSymbol ? norm[s + 1] : 0;
        if (mode == 1) return;
        LoadSlotNorm(slot);
        BuildCTable(slot, maxSymbol, tableLog);
    }

    void LoadSlotNorm(int slot)
    {
        for (int s = 0; s <= SlotMax[slot]; s++) NormCount[s + 1] = SlotNorm[(slot - 1) * 64 + s + 1];
    }

    // ---------------------------------------------------------------------------------------- Output / bits
    void PutByte(int value) => OutTB.Append((byte)value);
    void PutBlockByte(int value) => BlockTB.Append((byte)value);
    void PutLE(long value, int count)
    {
        for (int i = 1; i <= count; i++) { OutTB.Append((byte)(value % 256)); value /= 256; }
    }

    void AddBits(long value, int n)
    {
        if (n == 0) return;
        BwAcc += (value % Pow2B[n + 1]) * Pow2B[BwCount + 1];
        BwCount += n;
        FlushBits();
    }

    void BitCloseStream() { AddBits(1, 1); BitFlushPartial(); }

    void BitFlushPartial()
    {
        if (BwCount > 0) BlockTB.Append((byte)BwAcc);
        BwAcc = 0;
        BwCount = 0;
    }

    // ---------------------------------------------------------------------------------------- FSE
    void NormalizeCounts(int maxSymbol, int tableLog, int total)
    {
        long scale = Pow2B[tableLog + 1];
        int used = 0, diff, largest;
        for (int s = 0; s <= maxSymbol; s++)
        {
            NormCount[s + 1] = 0;
            if (HistCount[s + 1] > 0)
            {
                if (HistCount[s + 1] * scale < total) { NormCount[s + 1] = -1; used++; }
                else
                {
                    NormCount[s + 1] = (int)((HistCount[s + 1] * scale * 2 + total) / (2L * total));
                    if (NormCount[s + 1] < 1) NormCount[s + 1] = 1;
                    used += NormCount[s + 1];
                }
            }
        }
        diff = (int)(scale - used);
        while (diff != 0)
        {
            largest = 0;
            for (int s = 1; s <= maxSymbol; s++)
                if (NormCount[s + 1] > NormCount[largest + 1]) largest = s;
            if (diff > 0) { NormCount[largest + 1] += diff; diff = 0; }
            else
            {
                if (NormCount[largest + 1] <= 1) throw new InvalidOperationException("The zstd codec cannot run on this platform.");
                NormCount[largest + 1]--;
                diff++;
            }
        }
    }

    void WriteNCount(int maxSymbol, int tableLog)
    {
        int remaining = (int)Pow2B[tableLog + 1] + 1;
        int threshold = (int)Pow2B[tableLog + 1];
        int nbBits = tableLog + 1;
        int s = 0, start, count, max;
        bool previous0 = false;
        AddBits(tableLog - 5, 4);
        while (s <= maxSymbol && remaining > 1)
        {
            if (previous0)
            {
                start = s;
                while (s <= maxSymbol && NormCount[s + 1] == 0) s++;
                while (start + 3 <= s) { AddBits(3, 2); start += 3; }
                AddBits(s - start, 2);
            }
            count = NormCount[s + 1];
            s++;
            max = 2 * threshold - 1 - remaining;
            if (count < 0) remaining += count; else remaining -= count;
            count++;
            if (count >= threshold) count += max;
            if (count < max) AddBits(count, nbBits - 1); else AddBits(count, nbBits);
            previous0 = count == 1;
            if (remaining < 1) throw new InvalidOperationException("The zstd codec cannot run on this platform.");
            while (remaining < threshold) { nbBits--; threshold /= 2; }
        }
        if (remaining != 1) throw new InvalidOperationException("The zstd codec cannot run on this platform.");
        BitFlushPartial();
    }

    void BuildCTable(int slot, int maxSymbol, int tableLog)
    {
        int size = (int)Pow2B[tableLog + 1];
        int high = size - 1;
        int b = (slot - 1) * 512;
        int sb = (slot - 1) * 64;
        int step, pos, total = 0, maxBitsOut;
        Cumul[1] = 0;
        for (int s = 0; s <= maxSymbol; s++)
            if (NormCount[s + 1] == -1)
            {
                Cumul[s + 2] = Cumul[s + 1] + 1;
                TableSymbol[high + 1] = s;
                high--;
            }
            else Cumul[s + 2] = Cumul[s + 1] + NormCount[s + 1];
        step = size / 2 + size / 8 + 3;
        pos = 0;
        for (int s = 0; s <= maxSymbol; s++)
            for (int i = 1; i <= NormCount[s + 1]; i++)
            {
                TableSymbol[pos + 1] = s;
                do { pos = (pos + step) % size; } while (!(pos <= high));
            }
        for (int u = 0; u <= size - 1; u++)
        {
            int s = TableSymbol[u + 1];
            CState[b + Cumul[s + 1] + 1] = size + u;
            Cumul[s + 1]++;
        }
        for (int s = 0; s <= maxSymbol; s++)
            switch (NormCount[s + 1])
            {
                case 0:
                    DeltaNbBits[sb + s + 1] = (tableLog + 1) * 65536 - size;
                    break;
                case -1:
                case 1:
                    DeltaNbBits[sb + s + 1] = tableLog * 65536 - size;
                    DeltaFindState[sb + s + 1] = total - 1;
                    total++;
                    break;
                default:
                    maxBitsOut = tableLog - HighBit(NormCount[s + 1] - 1);
                    DeltaNbBits[sb + s + 1] = (int)(maxBitsOut * 65536 - NormCount[s + 1] * Pow2B[maxBitsOut + 1]);
                    DeltaFindState[sb + s + 1] = total - NormCount[s + 1];
                    total += NormCount[s + 1];
                    break;
            }
        CTableLog[slot] = tableLog;
    }

    int FseInitState(int slot, int symbol)
    {
        int idx = (slot - 1) * 64 + symbol + 1;
        int nbBitsOut = (DeltaNbBits[idx] + 32768) / 65536;
        int stateValue = nbBitsOut * 65536 - DeltaNbBits[idx];
        return CState[(slot - 1) * 512 + (int)(stateValue / Pow2B[nbBitsOut + 1]) + DeltaFindState[idx] + 1];
    }

    void FseEncode(int slot, ref int state, int symbol)
    {
        int idx = (slot - 1) * 64 + symbol + 1;
        int nbBitsOut = (state + DeltaNbBits[idx]) / 65536;
        AddBits(state, nbBitsOut);
        state = CState[(slot - 1) * 512 + (int)(state / Pow2B[nbBitsOut + 1]) + DeltaFindState[idx] + 1];
    }

    void FseFlushState(int slot, int state) => AddBits(state, CTableLog[slot]);
}
