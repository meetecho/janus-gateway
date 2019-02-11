#!/bin/bash

set -eu

TARGET=${1-"rtcp_fuzzer"}
OUT=${OUT-"$(pwd)/out"}
SRC=$(dirname $(pwd))
echo "Executing fuzzer $TARGET"

# run fuzzer
cd "$OUT"
mkdir -p "$TARGET"_corpus
mkdir -p "$TARGET"_seed_corpus
if [ -f "${TARGET}_seed_corpus.zip" ]; then
	echo "Extracting corpus seed data"
	unzip -oq "$TARGET"_seed_corpus.zip -d "$TARGET"_seed_corpus
fi
# Use -max_len=65535 for network protocols
ASAN_OPTIONS=detect_leaks=1 ./$TARGET -artifact_prefix="./$TARGET-" -print_final_stats=0 -print_corpus_stats=0 -print_coverage=0 -jobs=4 "$TARGET"_corpus "$TARGET"_seed_corpus
# tail -f fuzz*.log

# run standalone fuzzer or libFuzzer without fuzzing (regression testing)
# ASAN_OPTIONS=detect_leaks=1 ./$TARGET "$TARGET"_seed_corpus/*

# run fuzzer for coverage testing
# LLVM_PROFILE_FILE="$TARGET".profraw ./$TARGET "$TARGET"_seed_corpus/*
# llvm-profdata merge -sparse "$TARGET".profraw -o "$TARGET".profdata
# llvm-cov show "$TARGET" -instr-profile="$TARGET".profdata "$SRC"/rtcp.c -use-color -format=html > /tmp/"$TARGET"_coverage.html

# dump crashing pattern
# hexdump -C "$TARGET"-crash-458003b01372ea8ae6456f86da40d3b1d32d905d

# rerun to reproduce
# ./$TARGET "$TARGET"-crash-458003b01372ea8ae6456f86da40d3b1d32d905d

# rerun with GDB to reproduce and debug
# ASAN_OPTIONS=abort_on_error=1 gdb --args ./$TARGET "$TARGET"-crash-458003b01372ea8ae6456f86da40d3b1d32d905d

# Convert to pcap
# od -Ax -tx1 -v crash-458003b01372ea8ae6456f86da40d3b1d32d905d > crash.hex
# text2pcap -u1000,2000 crash.hex crash.pcap

