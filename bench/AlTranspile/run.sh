#!/bin/sh
# Transpile the AL Brotli codeunit to C# and run its tests : run.sh <file or dir>... [--levels ...]
# COUNT=1 run.sh --profile-run <file> [Level] [Profile] : statements / calls per procedure (AL time model)
set -e
cd "$(dirname "$0")"
B=../../brotli
python3 al2cs.py $B/TOOBrotliDataCompression.Codeunit.al $B/TOOBrotliLevel.Enum.al $B/TOOBrotliProfile.Enum.al ${COUNT:+--count} > Generated.cs
dotnet build -c Release -v q -nologo 2>&1 | grep -E "error|Build succeeded" | sort -u
dotnet bin/Release/net8.0/AlBrotliTest.dll $B/resources "$@"
