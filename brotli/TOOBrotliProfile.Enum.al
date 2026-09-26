/*
    Data profile of the pure-AL Brotli encoder (codeunit "TOO Brotli Data Compression"), chooses the parser settings behind
    each level (same as the zstd codec) :
    General    = default, tuned on general files : the hashed match length and search effort follow the input size.
    ColumnData = tuned on binary column-oriented exports of SQL table data : 6-byte matches, speed limits.
*/
enum 51161 "TOO Brotli Profile"
{
    Extensible = false;

    value(0; General)
    {
        Caption = 'General', Comment = 'Général';
    }
    value(1; ColumnData)
    {
        Caption = 'Column data', Comment = 'Données en colonnes';
    }
}
