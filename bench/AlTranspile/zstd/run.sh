#!/bin/sh
# Transpile the AL zstd codeunit to C# and run its tests (streams checked with zstd -d) : run.sh <file or dir>... [--levels ...]
# run.sh --hashes <files> : size + SHA-256 per stream (output identity) ; COUNT=1 run.sh --profile-corpus|--profile-run Level Profile <files>
set -e
cd "$(dirname "$0")"
Z=../../../zstd
python3 ../al2cs.py $Z/TOOZSTDDataCompression.Codeunit.al $Z/TOOZSTDLevel.Enum.al $Z/TOOZSTDProfile.Enum.al ${COUNT:+--count} > Generated.cs
dotnet build -c Release -v q -nologo 2>&1 | grep -E "error|Build succeeded" | sort -u
dotnet bin/Release/net8.0/AlZstdTest.dll "$@"
