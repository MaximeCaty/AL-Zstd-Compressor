/*
    Pure-AL zStandard compression level (codeunit "TOO ZSTD Data Compression"). Measured on column-oriented exports :
    Fast = double fast parser, about 0-5 % smaller than Gzip ; Medium = lazy parser with speed limits + long-distance
    matching, 5-10 % smaller ; Heavy = full lazy search + long-distance matching, 10-15 % smaller. All slower than Gzip.
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
