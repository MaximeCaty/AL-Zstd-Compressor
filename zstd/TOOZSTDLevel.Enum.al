/*
    Pure-AL zStandard compression level (codeunit "TOO ZSTD Data Compression"). Measured on column-oriented exports
    (profile ColumnData) : Fast = double fast parser, about 0-5 % smaller than Gzip ; Medium = lazy parser with speed
    limits + long-distance matching, 5-10 % smaller ; Heavy = full lazy search + long-distance matching, 10-15 % smaller.
    On general files (profile General) : Fast ~4 %, Medium ~12 %, Heavy ~13 % smaller (1-7 % below 256 KB).
    All slower than Gzip.
*/
enum 51150 "TOO ZSTD Level"
{
    Extensible = false;

    value(0; Fast)
    {
        Caption = 'Fast', Comment = 'Rapide';
    }
    value(1; Medium)
    {
        Caption = 'Medium', Comment = 'Moyen';
    }
    value(2; Heavy)
    {
        Caption = 'Heavy', Comment = 'Élevé';
    }
}
