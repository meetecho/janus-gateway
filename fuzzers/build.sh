#!/bin/bash -eu

ENV=${ENV-"local"}

# Try to get these vars from the environment
# Fallback to values used for local testing
SRC=${SRC-"$(dirname $(dirname $(pwd)))"}
OUT=${OUT-"$(pwd)/out"}
WORK=${WORK-"$(pwd)"}
CC=${CC-"clang"}
FUZZ_CFLAGS=""
FUZZ_LDFLAGS=""
FUZZ_CCLD=""
FUZZ_ENGINE=${LIB_FUZZING_ENGINE-""}

if [ "$ENV" == "oss-fuzz" ]; then
	# CXX and CXXFLAGS are used as linker and linker flags in oss-fuzz
	FUZZ_CFLAGS=$CFLAGS
	FUZZ_LDFLAGS=$CXXFLAGS
	FUZZ_CCLD=$CXX
elif [ "$ENV" == "local" ]; then
	# For address and undefined behaviour sanitizer
	FUZZ_CFLAGS=${CFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"}
	FUZZ_LDFLAGS=${LDFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fsanitize=fuzzer"}
	# For coverage testing use
	# 	FUZZ_CFLAGS=${CFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link"}
	# 	FUZZ_LDFLAGS=${LDFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer"}
	FUZZ_CCLD=$CC
fi

# build and archive necessary Janus objects
cd $SRC/janus-gateway
./autogen.sh
./configure CC="$CC" CFLAGS="$FUZZ_CFLAGS" --disable-docs --disable-post-processing --disable-turn-rest-api --disable-all-transports --disable-all-plugins --disable-all-handlers
make clean
JANUS_OBJECTS="janus-log.o janus-utils.o janus-rtcp.o"
make -j$(nproc) $JANUS_OBJECTS
JANUS_LIB="$WORK/janus-lib.a"
ar rcs $JANUS_LIB $JANUS_OBJECTS

# Fetch dependencies
DEPS_CFLAGS=$(pkg-config --cflags glib-2.0)
DEPS_LIB="$(find /usr -name libglib-2.0.a | head -n 1) $(find /usr -name libjansson.a | head -n 1)"

# build fuzzers
mkdir -p $OUT
fuzzers=$(find $SRC/janus-gateway/fuzzers/ -name "*.c")
for sourceFile in $fuzzers; do
  fuzzerName=$(basename $sourceFile .c)
  echo "Building $fuzzerName"
  $CC -c $FUZZ_CFLAGS $DEPS_CFLAGS -I. $sourceFile -o $WORK/$fuzzerName.o
  $FUZZ_CCLD $FUZZ_LDFLAGS $WORK/${fuzzerName}.o -o $OUT/${fuzzerName} $FUZZ_ENGINE $JANUS_LIB $DEPS_LIB
  
  if [ -d "$SRC/janus-gateway/fuzzers/corpora/${fuzzerName}" ]; then
	echo "Exporting $fuzzerName corpus"
	zip -jqr --exclude=*LICENSE* $OUT/${fuzzerName}_seed_corpus.zip $SRC/janus-gateway/fuzzers/corpora/${fuzzerName}
  fi
done
