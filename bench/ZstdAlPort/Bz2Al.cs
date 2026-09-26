/*
    Thought experiment : bzip2 (format of bzip2 1.0.x, readable by `bzip2 -d`, 7-Zip, SharpZipLib...) written as it would be
    in pure AL, to estimate its AL speed. Not a port of an existing AL object : the code follows AL constraints so that the
    statement count is realistic :
    - no bit operators in AL : shifts are * / div by Pow2, XOR (CRC32) goes through a 64 KB XorTbl, 4 byte lookups per byte ;
    - arrays capped at 1M elements : one 900 KB block (bzip2 -9) fits ;
    - bytes read as Latin-1 chars (InText[i]), output appended 2 bytes per TextBuilder.Append (PairTbl trick).
    Every AL statement a loop would execute is counted in St[stage] (a statement, an if / while test, a for step = 1),
    appends in Appends. AL time = statements x StmtNs + appends x AppendNs (README costs : ~20 ns per statement from the
    fitted model, 4-statement chain insert = 79 ns ; TextBuilder.Append 68-76 ns).

    Encoder : RLE1 + CRC -> least rotation (Lyndon word : its suffix order = its rotation order, so a plain suffix array gives
    the cyclic BWT) -> SA-IS -> BWT -> MTF + zero-run RUNA / RUNB -> 2..6 Huffman tables, selectors every 50 symbols,
    NIters refinement passes (bzip2 : 4) -> MSB-first bitstream.
    Decoder : table Huffman (2^maxLen lookup per table) -> RUNA / RUNB + inverse MTF -> inverse BWT (Next vector) ->
    inverse RLE1 -> CRC (optional, like the zstd decoder that skips its checksum).
*/
namespace ZstdAlPort;

public sealed class Bz2Al
{
    public const int SRle1 = 0, SCrc = 1, SRot = 2, SSais = 3, SBwt = 4, SMtf = 5, SHuf = 6, SEmit = 7,
        DHuf = 8, DMtf = 9, DIbwt = 10, DRle1 = 11, DCrc = 12, DTbl = 13;
    public static readonly string[] StageNames = { "RLE1", "CRC", "rotation", "SA-IS", "BWT", "MTF+RLE2", "Huffman tables", "bit output",
        "Huffman decode", "RLE2+MTF inv", "inverse BWT", "RLE1 inv", "CRC (dec)", "decode tables" };
    public readonly long[] St = new long[14];
    public long EncAppends, DecAppends;
    public int NIters = 4;
    public bool NoMtf; // experiment : BWT bytes coded directly (runs of the previous byte as RUNA / RUNB), not bzip2-decodable
    public int BlockMax = 900000 - 19;

    static readonly uint[] CrcTbl = MakeCrc();
    static uint[] MakeCrc()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i << 24;
            for (int k = 0; k < 8; k++) c = (c & 0x80000000) != 0 ? (c << 1) ^ 0x04c11db7 : c << 1;
            t[i] = c;
        }
        return t;
    }

    // ================================================================================================= Encoder
    ByteBuilder Out;
    long BwAcc; int BwCnt;

    void BsW(int n, long v)
    {
        // AL : BwAcc := BwAcc * Pow2[n] + v ; BwCnt += n ; if BwCnt >= 16 then flush 2 bytes (PairTbl)
        BwAcc = BwAcc * (1L << n) + v;
        BwCnt += n;
        while (BwCnt >= 16)
        {
            long pair = BwAcc / (1L << (BwCnt - 16));
            Out.Append((byte)(pair >> 8)); Out.Append((byte)(pair & 255));
            BwAcc %= 1L << (BwCnt - 16);
            BwCnt -= 16;
            St[SEmit] += 4; EncAppends++;
        }
    }

    void BsFlush()
    {
        while (BwCnt >= 8) { Out.Append((byte)(BwAcc >> (BwCnt - 8))); BwCnt -= 8; BwAcc &= (1L << BwCnt) - 1; }
        if (BwCnt > 0) { Out.Append((byte)(BwAcc << (8 - BwCnt))); BwCnt = 0; BwAcc = 0; }
    }

    public byte[] Compress(byte[] input)
    {
        Out = new ByteBuilder();
        BwAcc = 0; BwCnt = 0;
        Out.Append((byte)'B'); Out.Append((byte)'Z'); Out.Append((byte)'h'); Out.Append((byte)'9');
        uint combined = 0;
        var block = new byte[BlockMax + 8];
        int pos = 0;
        while (pos < input.Length)
        {
            // RLE1 + CRC over the block's input bytes
            int nb = 0, runChar = -1, runLen = 0;
            uint crc = 0xFFFFFFFF;
            int start = pos;
            while (pos < input.Length)
            {
                int c = input[pos];
                St[SRle1] += 2; // c := InText[Pos] ; if (c = RunChar) and (RunLen < 255)
                if (c == runChar && runLen < 255) { runLen++; St[SRle1]++; }
                else
                {
                    if (runLen > 0) nb = FlushRun(block, nb, runChar, runLen);
                    St[SRle1] += 2;
                    if (nb >= BlockMax) break;
                    runChar = c; runLen = 1; St[SRle1] += 2;
                }
                crc = (crc << 8) ^ CrcTbl[(crc >> 24) ^ (uint)c];
                St[SCrc] += 5; // 4 XorTbl lookups (one per CRC byte) + index
                pos++; St[SRle1]++;
            }
            if (pos >= input.Length && runLen > 0) nb = FlushRun(block, nb, runChar, runLen);
            crc = ~crc;
            combined = ((combined << 1) | (combined >> 31)) ^ crc;
            CompressBlock(block, nb, crc);
            _ = start;
        }
        BsW(24, 0x177245); BsW(24, 0x385090);
        BsW(16, combined >> 16); BsW(16, combined & 0xffff);
        BsFlush();
        return Out.ToArray();
    }

    int FlushRun(byte[] block, int nb, int ch, int len)
    {
        // AL : a run < 4 is copied, else 4 chars + count byte (Empty.PadRight : 1 statement, + count)
        if (len < 4) { for (int i = 0; i < len; i++) block[nb++] = (byte)ch; St[SRle1] += 2; }
        else { for (int i = 0; i < 4; i++) block[nb++] = (byte)ch; block[nb++] = (byte)(len - 4); St[SRle1] += 4; }
        return nb;
    }

    void CompressBlock(byte[] blk, int n, uint crc)
    {
        // --- least rotation (two-pointer, Booth-like) ; periodic block : BWT of one period, chars repeated
        int i = 0, j = 1, k = 0;
        while (i < n && j < n && k < n)
        {
            int a = blk[(i + k) % n], b = blk[(j + k) % n];
            St[SRot] += 4;
            if (a == b) { k++; St[SRot]++; }
            else
            {
                if (a > b) i += k + 1; else j += k + 1;
                if (i == j) j++;
                k = 0; St[SRot] += 4;
            }
        }
        int rot = Math.Min(i, j);
        int period = n;
        if (k >= n) period = Math.Abs(i - j) == 0 ? n : Math.Abs(i - j);
        if (n == 1) { rot = 0; period = 1; }
        int m = period; // primitive length
        // rotated Lyndon word r[0..m-1] = blk[rot..], plus sentinel 0 (bytes + 1)
        var s = new int[m + 1];
        for (int x = 0; x < m; x++) s[x] = blk[(x + rot) % n] + 1;
        s[m] = 0;
        St[SRot] += 2L * m;
        var sa = new int[m + 1];
        Sais(s, 0, sa, 0, m + 1, 257, 0);
        // --- BWT : L[r] = r[SA[r] - 1] (cyclic), skip the sentinel row SA[0] = m
        var L = new byte[n];
        int origRow = -1, rep = n / m;
        int origStart = ((n - rot) % n) % m; // the original rotation, within one period
        int outp = 0;
        for (int r = 1; r <= m; r++)
        {
            int p = sa[r];
            byte ch = (byte)(s[(p + m - 1) % m] - 1);
            if (p == origStart) origRow = outp;
            for (int t = 0; t < rep; t++) L[outp++] = ch;
            St[SBwt] += 4;
        }
        int origPtr = origRow;
        // --- MTF + RLE2
        var inUse = new bool[256];
        for (int x = 0; x < n; x++) inUse[L[x]] = true;
        St[SMtf] += n; // in AL : folded into the MTF loop histogram (1 statement)
        var unseqToSeq = new int[256];
        int nInUse = 0;
        for (int x = 0; x < 256; x++) if (inUse[x]) unseqToSeq[x] = nInUse++;
        int alphaSize = NoMtf ? nInUse + 3 : nInUse + 2, EOB = NoMtf ? nInUse + 2 : nInUse + 1;
        var mtfv = new int[n + 1];
        var mtfFreq = new int[260];
        var yy = new int[256];
        for (int x = 0; x < nInUse; x++) yy[x] = x;
        int nMTF = 0, zPend = 0;
        for (int x = 0; x < n; x++)
        {
            int ll = unseqToSeq[L[x]];
            St[SMtf] += 2;
            if (NoMtf)
            {
                if (yy[0] == ll && x > 0) { zPend++; continue; }
                if (zPend > 0) { nMTF = PutRun(mtfv, mtfFreq, nMTF, zPend); zPend = 0; }
                yy[0] = ll; mtfv[nMTF++] = ll + 2; mtfFreq[ll + 2]++;
                continue;
            }
            if (yy[0] == ll) { zPend++; St[SMtf]++; }
            else
            {
                if (zPend > 0) { nMTF = PutRun(mtfv, mtfFreq, nMTF, zPend); zPend = 0; }
                // move to front : shift until found
                int rtmp = yy[1]; yy[1] = yy[0];
                int jj = 1;
                St[SMtf] += 4;
                while (ll != rtmp) { jj++; int t2 = rtmp; rtmp = yy[jj]; yy[jj] = t2; St[SMtf] += 5; }
                yy[0] = rtmp;
                mtfv[nMTF++] = jj + 1; mtfFreq[jj + 1]++;
                St[SMtf] += 4;
            }
        }
        if (zPend > 0) nMTF = PutRun(mtfv, mtfFreq, nMTF, zPend);
        mtfv[nMTF++] = EOB; mtfFreq[EOB]++;

        // --- Huffman tables (bzip2 sendMTFValues)
        int nGroups = nMTF < 200 ? 2 : nMTF < 600 ? 3 : nMTF < 1200 ? 4 : nMTF < 2400 ? 5 : 6;
        var len = new int[nGroups, 260];
        {
            int nPart = nGroups, remF = nMTF, gs = 0;
            while (nPart > 0)
            {
                int tFreq = remF / nPart, ge = gs - 1, aFreq = 0;
                while (aFreq < tFreq && ge < alphaSize - 1) { ge++; aFreq += mtfFreq[ge]; }
                if (ge > gs && nPart != nGroups && nPart != 1 && ((nGroups - nPart) % 2 == 1)) { aFreq -= mtfFreq[ge]; ge--; }
                for (int v = 0; v < alphaSize; v++) len[nPart - 1, v] = (v >= gs && v <= ge) ? 0 : 15;
                nPart--; gs = ge + 1; remF -= aFreq;
            }
        }
        int nSelectors = (nMTF + 49) / 50;
        var selector = new int[nSelectors];
        var rfreq = new int[nGroups, 260];
        var cost = new int[6];
        for (int iter = 0; iter < NIters; iter++)
        {
            Array.Clear(rfreq);
            int gs = 0, nSel = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1);
                for (int t = 0; t < nGroups; t++) cost[t] = 0;
                for (int x = gs; x <= ge; x++)
                {
                    int icv = mtfv[x];
                    for (int t = 0; t < nGroups; t++) cost[t] += len[t, icv];
                    St[SHuf] += 2 + nGroups; // for step + icv + one cost add per table (unrolled by a case on nGroups)
                }
                int bt = 0, bc = cost[0];
                for (int t = 1; t < nGroups; t++) if (cost[t] < bc) { bc = cost[t]; bt = t; }
                selector[nSel++] = bt;
                for (int x = gs; x <= ge; x++) rfreq[bt, mtfv[x]]++;
                St[SHuf] += 2L * (ge - gs + 1) + 4 + 2 * nGroups;
                gs = ge + 1;
            }
            for (int t = 0; t < nGroups; t++) MakeCodeLengths(len, rfreq, t, alphaSize, 17);
        }
        // codes (canonical, as bzip2 assignCodes)
        var code = new int[nGroups, 260];
        for (int t = 0; t < nGroups; t++)
        {
            int minL = 32, maxL = 0;
            for (int v = 0; v < alphaSize; v++) { minL = Math.Min(minL, len[t, v]); maxL = Math.Max(maxL, len[t, v]); }
            int vec = 0;
            for (int L2 = minL; L2 <= maxL; L2++) { for (int v = 0; v < alphaSize; v++) if (len[t, v] == L2) code[t, v] = vec++; vec <<= 1; }
            St[SHuf] += 2L * alphaSize * (maxL - minL + 2);
        }

        // --- block header
        BsW(24, 0x314159); BsW(24, 0x265359);
        BsW(16, crc >> 16); BsW(16, crc & 0xffff);
        BsW(1, 0);
        BsW(24, origPtr);
        // symbol map
        var inUse16 = new bool[16];
        for (int x = 0; x < 16; x++) for (int y = 0; y < 16; y++) if (inUse[x * 16 + y]) inUse16[x] = true;
        for (int x = 0; x < 16; x++) BsW(1, inUse16[x] ? 1 : 0);
        for (int x = 0; x < 16; x++) if (inUse16[x]) for (int y = 0; y < 16; y++) BsW(1, inUse[x * 16 + y] ? 1 : 0);
        BsW(3, nGroups);
        BsW(15, nSelectors);
        // selectors, MTF + unary
        var pos = new int[6];
        for (int t = 0; t < nGroups; t++) pos[t] = t;
        for (int x = 0; x < nSelectors; x++)
        {
            int v = selector[x], jj = 0, tmp = pos[0];
            while (v != tmp) { jj++; int t2 = tmp; tmp = pos[jj]; pos[jj] = t2; }
            pos[0] = tmp;
            for (int y = 0; y < jj; y++) BsW(1, 1);
            BsW(1, 0);
            St[SEmit] += 4 + 2L * jj;
        }
        // coding tables (delta lengths)
        for (int t = 0; t < nGroups; t++)
        {
            int curr = len[t, 0];
            BsW(5, curr);
            for (int v = 0; v < alphaSize; v++)
            {
                while (curr < len[t, v]) { BsW(2, 2); curr++; }
                while (curr > len[t, v]) { BsW(2, 3); curr--; }
                BsW(1, 0);
                St[SEmit] += 4;
            }
        }
        // symbols
        {
            int selCtr = 0, gs = 0;
            while (gs < nMTF)
            {
                int ge = Math.Min(gs + 49, nMTF - 1);
                int t = selector[selCtr++];
                St[SEmit] += 4;
                for (int x = gs; x <= ge; x++)
                {
                    int sym = mtfv[x];
                    BsW(len[t, sym], code[t, sym]);
                    St[SEmit] += 4; // for step, symbol, BwAcc update, BwCnt update (the flush is counted in BsW)
                }
                gs = ge + 1;
            }
        }
    }

    int PutRun(int[] mtfv, int[] mtfFreq, int nMTF, int zPend)
    {
        zPend--;
        St[SMtf] += 2;
        while (true)
        {
            int sym = (zPend & 1) != 0 ? 1 : 0; // RUNB : RUNA
            mtfv[nMTF++] = sym; mtfFreq[sym]++;
            St[SMtf] += 5;
            if (zPend < 2) break;
            zPend = (zPend - 2) / 2;
        }
        return nMTF;
    }

    void MakeCodeLengths(int[,] len, int[,] freq, int t, int alphaSize, int maxLen)
    {
        var heap = new int[264];
        var weight = new int[530];
        var parent = new int[530];
        long stc = 0;
        for (int i = 0; i < alphaSize; i++) weight[i + 1] = (freq[t, i] == 0 ? 1 : freq[t, i]) << 8;
        stc += alphaSize * 2;
        while (true)
        {
            int nNodes = alphaSize, nHeap = 0;
            heap[0] = 0; weight[0] = 0; parent[0] = -2;
            for (int i = 1; i <= alphaSize; i++) { parent[i] = -1; nHeap++; heap[nHeap] = i; stc += 4 + UpHeap(heap, weight, nHeap); }
            while (nHeap > 1)
            {
                int n1 = heap[1]; heap[1] = heap[nHeap]; nHeap--; stc += 4 + DownHeap(heap, weight, nHeap, 1);
                int n2 = heap[1]; heap[1] = heap[nHeap]; nHeap--; stc += 4 + DownHeap(heap, weight, nHeap, 1);
                nNodes++;
                parent[n1] = parent[n2] = nNodes;
                int w1 = weight[n1], w2 = weight[n2];
                weight[nNodes] = ((w1 & ~0xff) + (w2 & ~0xff)) | (1 + Math.Max(w1 & 0xff, w2 & 0xff));
                parent[nNodes] = -1;
                nHeap++; heap[nHeap] = nNodes;
                stc += 8 + UpHeap(heap, weight, nHeap);
            }
            bool tooLong = false;
            for (int i = 1; i <= alphaSize; i++)
            {
                int j = 0, k = i;
                while (parent[k] >= 0) { k = parent[k]; j++; stc += 3; }
                len[t, i - 1] = j;
                if (j > maxLen) tooLong = true;
                stc += 5;
            }
            if (!tooLong) break;
            for (int i = 1; i <= alphaSize; i++) { int j = weight[i] >> 8; j = 1 + j / 2; weight[i] = j << 8; stc += 4; }
        }
        St[SHuf] += stc;
    }

    static int UpHeap(int[] heap, int[] weight, int z)
    {
        int zz = z, tmp = heap[zz], c = 3;
        while (weight[tmp] < weight[heap[zz >> 1]]) { heap[zz] = heap[zz >> 1]; zz >>= 1; c += 3; }
        heap[zz] = tmp;
        return c;
    }

    static int DownHeap(int[] heap, int[] weight, int nHeap, int z)
    {
        int zz = z, tmp = heap[zz], c = 3;
        while (true)
        {
            int yy = zz << 1;
            c += 2;
            if (yy > nHeap) break;
            if (yy < nHeap && weight[heap[yy + 1]] < weight[heap[yy]]) yy++;
            c += 2;
            if (weight[tmp] < weight[heap[yy]]) break;
            heap[zz] = heap[yy]; zz = yy; c += 2;
        }
        heap[zz] = tmp;
        return c;
    }

    /// <summary>Suffix array of s (s[^1] = 0 unique smallest, values 0..K) : SA-IS below, statements counted in St.</summary>
    public void SuffixArray(int[] s, int[] sa, int K) => Sais(s, 0, sa, 0, s.Length, K, 0);

    // ------------------------------------------------------------------------------------------------- SA-IS
    // Nong-Zhang-Chan SA-IS, s[sOff .. sOff + n - 1], s[last] = 0 unique smallest ; SA[saOff ..]. Recursion keeps s1 at the
    // end of SA (as in the paper) ; in AL : SA / s as global arrays with offsets, t / buckets as local arrays.
    void Sais(int[] s, int sOff, int[] SA, int saOff, int n, int K, int depth)
    {
        var t = new bool[n];
        t[n - 1] = true;
        if (n > 1) t[n - 2] = false;
        for (int i = n - 3; i >= 0; i--) t[i] = s[sOff + i] < s[sOff + i + 1] || (s[sOff + i] == s[sOff + i + 1] && t[i + 1]);
        St[SSais] += 2L * n;
        var bkt = new int[K + 1];
        GetBuckets(s, sOff, n, K, bkt, true);
        for (int i = 0; i < n; i++) SA[saOff + i] = -1;
        for (int i = 1; i < n; i++) if (t[i] && !t[i - 1]) SA[saOff + (--bkt[s[sOff + i]])] = i;
        St[SSais] += 3L * n;
        InduceL(t, SA, saOff, s, sOff, bkt, n, K);
        InduceS(t, SA, saOff, s, sOff, bkt, n, K);
        int n1 = 0;
        for (int i = 0; i < n; i++) { int p = SA[saOff + i]; if (p > 0 && t[p] && !t[p - 1]) SA[saOff + n1++] = p; }
        St[SSais] += 3L * n;
        for (int i = n1; i < n; i++) SA[saOff + i] = -1;
        int name = 0, prev = -1;
        for (int i = 0; i < n1; i++)
        {
            int p = SA[saOff + i];
            bool diff = false;
            for (int d = 0; d < n; d++)
            {
                St[SSais] += 3;
                if (prev == -1 || s[sOff + p + d] != s[sOff + prev + d] || t[p + d] != t[prev + d]) { diff = true; break; }
                if (d > 0 && ((p + d > 0 && t[p + d] && !t[p + d - 1]) || (prev + d > 0 && t[prev + d] && !t[prev + d - 1]))) break;
            }
            if (diff) { name++; prev = p; }
            SA[saOff + n1 + p / 2] = name - 1;
            St[SSais] += 5;
        }
        St[SSais] += n - n1;
        for (int i = n - 1, j = n - 1; i >= n1; i--) if (SA[saOff + i] >= 0) SA[saOff + j--] = SA[saOff + i];
        St[SSais] += 2L * (n - n1);
        int s1Off = saOff + n - n1;
        if (name < n1) Sais(SA, s1Off, SA, saOff, n1, name - 1, depth + 1);
        else { for (int i = 0; i < n1; i++) SA[saOff + SA[s1Off + i]] = i; St[SSais] += 2L * n1; }
        GetBuckets(s, sOff, n, K, bkt, true);
        for (int i = 1, j = 0; i < n; i++) if (t[i] && !t[i - 1]) SA[s1Off + j++] = i;
        St[SSais] += 2L * n;
        for (int i = 0; i < n1; i++) SA[saOff + i] = SA[s1Off + SA[saOff + i]];
        for (int i = n1; i < n; i++) SA[saOff + i] = -1;
        St[SSais] += 2L * n1 + (n - n1);
        for (int i = n1 - 1; i >= 0; i--) { int j = SA[saOff + i]; SA[saOff + i] = -1; SA[saOff + (--bkt[s[sOff + j]])] = j; }
        St[SSais] += 4L * n1;
        InduceL(t, SA, saOff, s, sOff, bkt, n, K);
        InduceS(t, SA, saOff, s, sOff, bkt, n, K);
    }

    void GetBuckets(int[] s, int sOff, int n, int K, int[] bkt, bool end)
    {
        for (int i = 0; i <= K; i++) bkt[i] = 0;
        for (int i = 0; i < n; i++) bkt[s[sOff + i]]++;
        int sum = 0;
        for (int i = 0; i <= K; i++) { sum += bkt[i]; bkt[i] = end ? sum : sum - bkt[i]; }
        St[SSais] += 2L * n + 3L * (K + 1);
    }

    void InduceL(bool[] t, int[] SA, int saOff, int[] s, int sOff, int[] bkt, int n, int K)
    {
        GetBuckets(s, sOff, n, K, bkt, false);
        for (int i = 0; i < n; i++)
        {
            int j = SA[saOff + i] - 1;
            if (j >= 0 && !t[j]) SA[saOff + bkt[s[sOff + j]]++] = j;
        }
        St[SSais] += 3L * n + n / 2; // for step, j, test ; ~half the positions are L-type (store + bucket increment)
    }

    void InduceS(bool[] t, int[] SA, int saOff, int[] s, int sOff, int[] bkt, int n, int K)
    {
        GetBuckets(s, sOff, n, K, bkt, true);
        for (int i = n - 1; i >= 0; i--)
        {
            int j = SA[saOff + i] - 1;
            if (j >= 0 && t[j]) SA[saOff + (--bkt[s[sOff + j]])] = j;
        }
        St[SSais] += 3L * n + n / 2;
    }

    // ================================================================================================= Decoder
    byte[] In; int InPos; long BrAcc; int BrCnt;

    int BsR(int n)
    {
        while (BrCnt < n) { BrAcc = (BrAcc << 8) | (InPos < In.Length ? In[InPos] : 0); InPos++; BrCnt += 8; }
        int v = (int)(BrAcc >> (BrCnt - n)) & ((1 << n) - 1);
        BrCnt -= n;
        BrAcc &= (1L << BrCnt) - 1;
        return v;
    }

    public bool VerifyCrc = true;

    public byte[] Decompress(byte[] input)
    {
        In = input; InPos = 4; BrAcc = 0; BrCnt = 0;
        var outB = new ByteBuilder();
        var ll = new byte[900000];
        var next = new int[900000];
        while (true)
        {
            long magic = ((long)BsR(24) << 24) | (long)BsR(24);
            if (magic == 0x177245385090L) break;
            if (magic != 0x314159265359L) throw new Exception("bad block magic");
            uint blockCrc = (uint)((BsR(16) << 16) | BsR(16));
            BsR(1);
            int origPtr = BsR(24);
            var inUse16 = new bool[16];
            for (int x = 0; x < 16; x++) inUse16[x] = BsR(1) == 1;
            var seqToUnseq = new int[256];
            int nInUse = 0;
            for (int x = 0; x < 16; x++) if (inUse16[x]) for (int y = 0; y < 16; y++) if (BsR(1) == 1) seqToUnseq[nInUse++] = x * 16 + y;
            int alphaSize = nInUse + 2, EOB = nInUse + 1;
            int nGroups = BsR(3), nSelectors = BsR(15);
            var selectorMtf = new int[nSelectors];
            for (int x = 0; x < nSelectors; x++) { int j = 0; while (BsR(1) == 1) j++; selectorMtf[x] = j; }
            var pos = new int[6];
            for (int t = 0; t < nGroups; t++) pos[t] = t;
            var selector = new int[nSelectors];
            for (int x = 0; x < nSelectors; x++)
            {
                int v = selectorMtf[x], tmp = pos[v];
                while (v > 0) { pos[v] = pos[v - 1]; v--; }
                pos[0] = tmp; selector[x] = tmp;
            }
            var len = new int[nGroups, 260];
            for (int t = 0; t < nGroups; t++)
            {
                int curr = BsR(5);
                for (int v = 0; v < alphaSize; v++)
                {
                    while (BsR(1) == 1) curr += BsR(1) == 0 ? 1 : -1;
                    len[t, v] = curr;
                }
            }
            // lookup tables : 2^maxLen entries per table (symbol, length)
            var maxLen = new int[nGroups];
            var dSym = new int[nGroups][];
            var dLen = new int[nGroups][];
            for (int t = 0; t < nGroups; t++)
            {
                int minL = 32, mx = 0;
                for (int v = 0; v < alphaSize; v++) { minL = Math.Min(minL, len[t, v]); mx = Math.Max(mx, len[t, v]); }
                maxLen[t] = mx;
                dSym[t] = new int[1 << mx]; dLen[t] = new int[1 << mx];
                int vec = 0;
                for (int L2 = minL; L2 <= mx; L2++)
                {
                    for (int v = 0; v < alphaSize; v++)
                        if (len[t, v] == L2)
                        {
                            int first = vec << (mx - L2), cnt = 1 << (mx - L2);
                            for (int e = 0; e < cnt; e++) { dSym[t][first + e] = v; dLen[t][first + e] = L2; }
                            St[DTbl] += 3L * cnt + 3; // AL : 2 array stores + for step per cell
                            vec++;
                        }
                    vec <<= 1;
                }
                St[DTbl] += 2L * alphaSize * (mx - minL + 2);
            }
            // symbols -> RUNA / RUNB + inverse MTF -> ll
            var yy = new int[256];
            for (int x = 0; x < 256; x++) yy[x] = x;
            var unzftab = new int[256];
            int nblock = 0, groupNo = -1, groupPos = 0, es = 0, N = 1, gT = 0, gMax = 0;
            while (true)
            {
                if (groupPos == 0) { groupNo++; groupPos = 50; gT = selector[groupNo]; gMax = maxLen[gT]; St[DHuf] += 4; }
                groupPos--;
                while (BrCnt < gMax) { BrAcc = (BrAcc << 8) | (InPos < In.Length ? In[InPos] : 0); InPos++; BrCnt += 8; St[DHuf] += 2; } // AL : 2 bytes per refill
                int peek = (int)(BrAcc >> (BrCnt - gMax)) & ((1 << gMax) - 1);
                int sym = dSym[gT][peek];
                BrCnt -= dLen[gT][peek];
                BrAcc &= (1L << BrCnt) - 1;
                St[DHuf] += 7; // group test, groupPos, refill test, peek, sym, count, mask
                if (sym <= 1)
                {
                    es += (sym + 1) * N; N *= 2;
                    St[DMtf] += 3;
                    continue;
                }
                if (es > 0)
                {
                    int uc = seqToUnseq[yy[0]];
                    unzftab[uc] += es;
                    for (int e = 0; e < es; e++) ll[nblock++] = (byte)uc;
                    St[DMtf] += 5 + 2L * es;
                    es = 0; N = 1;
                }
                St[DMtf] += 2;
                if (sym == EOB) break;
                {
                    int nn = sym - 1, uc = yy[nn];
                    for (int z = nn; z > 0; z--) yy[z] = yy[z - 1];
                    yy[0] = uc;
                    int b = seqToUnseq[uc];
                    ll[nblock++] = (byte)b; unzftab[b]++;
                    St[DMtf] += 7 + 2L * nn;
                }
            }
            // inverse BWT
            var cftab = new int[257];
            for (int x = 0; x < 256; x++) cftab[x + 1] = cftab[x] + unzftab[x];
            for (int x = 0; x < nblock; x++) next[cftab[ll[x]]++] = x;
            St[DIbwt] += 3L * nblock;
            int tPos = next[origPtr];
            // inverse RLE1 + CRC + output (2 bytes per append)
            uint crc = 0xFFFFFFFF;
            int last = -1, run = 0, pending = 0;
            for (int k = 0; k < nblock; k++)
            {
                int ch = ll[tPos]; tPos = next[tPos];
                St[DIbwt] += 3;
                if (run == 4)
                {
                    for (int r = 0; r < ch; r++) { outB.Append((byte)last); if (VerifyCrc) crc = (crc << 8) ^ CrcTbl[(crc >> 24) ^ (uint)last]; }
                    // AL : Empty.PadRight(ch, char) in one append ; CRC still per byte
                    St[DRle1] += 4; DecAppends++;
                    if (VerifyCrc) St[DCrc] += 5L * ch;
                    run = 0; last = -1;
                    continue;
                }
                if (ch == last) run++; else { last = ch; run = 1; }
                outB.Append((byte)ch);
                if (VerifyCrc) { crc = (crc << 8) ^ CrcTbl[(crc >> 24) ^ (uint)ch]; St[DCrc] += 5; }
                St[DRle1] += 5; // run test, compare, run update, pair assembly
                pending++;
                if (pending == 2) { pending = 0; DecAppends++; }
            }
            if (VerifyCrc && ~crc != blockCrc) throw new Exception("block CRC mismatch");
        }
        return outB.ToArray();
    }
}
