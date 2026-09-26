/*
    Pure-AL Brotli compression level (codeunit "TOO Brotli Data Compression") : the parser levels of the zstd codec.
    Fast = double fast parser ; Medium = lazy parser with speed limits + long-distance matching ; Heavy = full lazy search
    + long-distance matching. On general files (General profile), size vs GZip : Medium ~-15 %, Heavy ~-16 %.
*/
enum 51160 "TOO Brotli Level"
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
