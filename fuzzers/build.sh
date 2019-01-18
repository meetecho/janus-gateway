#!/bin/bash -eu

ENV=${ENV-"local"}

# Try to get these vars from the environment
# Fallback to values used for local testing
SRC=${SRC-"$(dirname $(dirname $(pwd)))"}
OUT=${OUT-"$(pwd)/out"}
WORK=${WORK-"$(pwd)"}
FUZZ_CC=${CC-"clang"}
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
	# Default configuration: use address and undefined behaviour sanitizers
	FUZZ_CFLAGS=${CFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"}
	FUZZ_LDFLAGS=${LDFLAGS-"-O1 -fno-omit-frame-pointer -g -ggdb3 -fsanitize=address,undefined -fsanitize-address-use-after-scope"}
	if [[ $FUZZ_CC == clang* ]]; then
		# For coverage testing with clang uncomment
		# FUZZ_CFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fprofile-instr-generate -fcoverage-mapping -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
		# FUZZ_LDFLAGS="-O1 -fno-omit-frame-pointer -g -ggdb3 -fprofile-instr-generate -fcoverage-mapping"

		# When clang is detected always use libFuzzer but link against
		# libFuzzer only if LIB_FUZZING_ENGINE has not been defined
		FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
		if [ ! -z $FUZZ_ENGINE ]; then
			FUZZ_LDFLAGS="$FUZZ_LDFLAGS -fsanitize=fuzzer-no-link"
		else
			FUZZ_LDFLAGS="$FUZZ_LDFLAGS -fsanitize=fuzzer"
		fi
	fi
	FUZZ_CCLD=$FUZZ_CC
fi

rm -f $WORK/*.a $WORK/*.o

# Build and archive necessary Janus objects
cd $SRC/janus-gateway
./autogen.sh
./configure CC="$FUZZ_CC" CFLAGS="$FUZZ_CFLAGS" --disable-docs --disable-post-processing --disable-turn-rest-api --disable-all-transports --disable-all-plugins --disable-all-handlers
make clean
JANUS_OBJECTS="janus-log.o janus-utils.o janus-rtcp.o janus-rtp.o"
make -j$(nproc) $JANUS_OBJECTS
JANUS_LIB="$WORK/janus-lib.a"
ar rcs $JANUS_LIB $JANUS_OBJECTS
cd -

# Fetch dependencies
DEPS_CFLAGS="$(pkg-config --cflags glib-2.0)"
DEPS_LIB="-Wl,-Bstatic $(pkg-config --libs glib-2.0) -pthread -Wl,-Bdynamic"

# Build standalone fuzzing engines
engines=$(find $SRC/janus-gateway/fuzzers/ -name "*standalone.c")
for sourceFile in $engines; do
  name=$(basename $sourceFile .c)
  echo "Building engine: $name"
  $FUZZ_CC -c $FUZZ_CFLAGS $sourceFile -o $WORK/$name.o
done

# Build Fuzzers
mkdir -p $OUT
fuzzers=$(find $SRC/janus-gateway/fuzzers/ -name "fuzz*.c")
for sourceFile in $fuzzers; do
  name=$(basename $sourceFile .c)
  echo "Building fuzzer: $name"

  $FUZZ_CC -c $FUZZ_CFLAGS $DEPS_CFLAGS -I. -I$SRC/janus-gateway $sourceFile -o $WORK/$name.o
  $FUZZ_CCLD $FUZZ_LDFLAGS $WORK/${name}.o -o $OUT/${name} $FUZZ_ENGINE $JANUS_LIB $DEPS_LIB
  
  if [ -d "$SRC/janus-gateway/fuzzers/corpora/${name}" ]; then
	echo "Exporting corpus: $name "
	zip -jqr --exclude=*LICENSE* $OUT/${name}_seed_corpus.zip $SRC/janus-gateway/fuzzers/corpora/${name}
  fi
done
