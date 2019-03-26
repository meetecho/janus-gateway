#!/bin/bash

set -eu

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

TARGET=${1:-"rtcp_fuzzer"}
CRASH_FILE=${2:-""}
if [[ ! -z "$CRASH_FILE" && "${CRASH_FILE:0:1}" != / && "${CRASH_FILE:0:2}" != ~[/a-z] ]]; then
	CRASH_FILE="$SCRIPTPATH"/"$CRASH_FILE"
fi
HALF_NCORES=$(expr $(nproc) / 2)
HALF_NCORES=$(($HALF_NCORES > 0 ? $HALF_NCORES : 1))
JOBS=${JOBS:-${HALF_NCORES}}
WORKERS=${WORKERS:-${HALF_NCORES}}
OUT=${OUT:-"$SCRIPTPATH/out"}
SRC=$(dirname $SCRIPTPATH)

echo "Fuzzer: $TARGET"
echo "Crash file/folder: $CRASH_FILE"
echo "Output dir: $OUT"

# run fuzzer
cd "$OUT"
mkdir -p "$TARGET"_corpus
mkdir -p "$TARGET"_seed_corpus
if [ -f "${TARGET}_seed_corpus.zip" ]; then
	echo "Extracting corpus seed data"
	unzip -oq "$TARGET"_seed_corpus.zip -d "$TARGET"_seed_corpus
fi
# Use -max_len=65535 for network protocols
if [ -z "$CRASH_FILE" ]; then
	ASAN_OPTIONS=detect_leaks=1 ./$TARGET -artifact_prefix="./$TARGET-" -print_final_stats=0 -print_corpus_stats=0 -print_coverage=0 -jobs=${JOBS} -workers=${WORKERS} "$TARGET"_corpus "$TARGET"_seed_corpus
	# tail -f fuzz*.log
elif [ -f "$CRASH_FILE" ]; then
	# rerun to reproduce with a supplied crash file
	ASAN_OPTIONS=detect_leaks=1 ./$TARGET $CRASH_FILE
	# rerun with GDB to reproduce and debug
	#ASAN_OPTIONS=abort_on_error=1 gdb --args ./$TARGET $CRASH_FILE
elif [ -d "$CRASH_FILE" ]; then
	# run without fuzzing, with an user supplied folder
	ASAN_OPTIONS=detect_leaks=1 ./$TARGET "$CRASH_FILE"/*
else
	echo "Invalid crash file/folder specified!"
	exit 1
fi

# run without fuzzing, using the extracted corpus dataset (regression testing)
# ASAN_OPTIONS=detect_leaks=1 ./$TARGET "$TARGET"_seed_corpus/*

# run fuzzer for coverage testing
# NAME="$TARGET".$(date +%s)
# LLVM_PROFILE_FILE="$NAME".profraw ./$TARGET "$TARGET"_seed_corpus/*
# llvm-profdata merge -sparse "$NAME".profraw -o "$NAME".profdata
# llvm-cov show "$TARGET" -instr-profile="$NAME".profdata "$SRC"/rtcp.c "$SRC"/rtp.c "$SRC"/utils.c -use-color -format=html > "$NAME".html

# dump crashing pattern
# hexdump -C "$TARGET"-crash-458003b01372ea8ae6456f86da40d3b1d32d905d

# Convert to pcap
# od -Ax -tx1 -v crash-458003b01372ea8ae6456f86da40d3b1d32d905d > crash.hex
# text2pcap -u1000,2000 crash.hex crash.pcap

