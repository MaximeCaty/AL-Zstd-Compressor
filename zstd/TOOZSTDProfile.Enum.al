/*
    Data profile of the pure-AL zStandard encoder (codeunit "TOO ZSTD Data Compression"), chooses the parser settings
    behind each level :
    General    = default, tuned on general files (JSON, XML, CSV, text, source code, PDF, enwik8) : the hashed match length
                 and the search effort follow the input size (short matches and deep search on small files).
    ColumnData = tuned on binary column-oriented exports of SQL table data (company data import / export tool) :
                 6-byte matches, speed limits.
*/
enum 51151 "TOO ZSTD Profile"
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
