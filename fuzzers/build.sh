#!/bin/bash -eu

# Load script configuration
source $(dirname $0)/config.sh

# Set fuzzing environment
# Fallback to local
FUZZ_ENV=${FUZZ_ENV-$DEFAULT_ENV}

# Set working paths from the environment
# Fallback to values used for local testing
SRC=${SRC-$DEFAULT_SRC}
OUT=${OUT-$DEFAULT_OUT}
WORK=${WORK-$DEFAULT_WORK}
JANUSGW=${JANUSGW-$DEFAULT_JANUSGW}

# Set compiler from the environment
# Fallback to clang
FUZZ_CC=${CC-$DEFAULT_CC}

# Set linker from the environment (CXX is used as linker in oss-fuzz)
# Fallback to clang
FUZZ_CCLD=${CXX-${CC-$DEFAULT_CCLD}}

# Set CFLAGS from the environment
# Fallback to using address and undefined behaviour sanitizers
FUZZ_CFLAGS=${CFLAGS-$DEFAULT_CFLAGS}
# Allow users to optionally append extra CFLAGS
ECFLAGS=${ECFLAGS-""}
FUZZ_CFLAGS="${FUZZ_CFLAGS} ${ECFLAGS}"

# Set LDFLAGS from the environment (CXXFLAGS var is used for linker flags in oss-fuzz)
# Fallback to using address and undefined behaviour sanitizers
FUZZ_LDFLAGS=${CXXFLAGS-${LDFLAGS-$DEFAULT_LDFLAGS}}
# Allow users to optionally append extra LDFLAGS
ELDFLAGS=${ELDFLAGS-""}
FUZZ_LDFLAGS="${FUZZ_LDFLAGS} ${ELDFLAGS}"

# Set fuzzing engine from the environment (optional)
FUZZ_ENGINE=${LIB_FUZZING_ENGINE-""}

# Use shared libraries in local execution
FUZZ_DEPS="$DEPS_LIB"
if [[ $FUZZ_ENV == "local" ]]; then
	FUZZ_DEPS="$DEPS_LIB_SHARED"
fi
# Mess with the flags only in local execution
if [[ $FUZZ_ENV == "local" &&  $FUZZ_CC == clang* ]]; then
	# For coverage testing with clang uncomment
	# 	FUZZ_CFLAGS="$COVERAGE_CFLAGS"
	# 	FUZZ_LDFLAGS="$COVERAGE_LDFLAGS"

	# Add fuzzer CFLAG only if not present
	if [[ ! $FUZZ_CFLAGS =~ .*-fsanitize=([^\s].*)*fuzzer(-.*)* ]]; then
		FUZZ_CFLAGS="$FUZZ_CFLAGS -fsanitize=fuzzer-no-link"
	fi
	# Add fuzzer LDFLAG only if not present
	if [[ ! $FUZZ_LDFLAGS =~ .*-fsanitize=([^\s].*)*fuzzer(-.*)* ]]; then
		# Link against libFuzzer only if FUZZ_ENGINE has not been set
		if [[ ! -z $FUZZ_ENGINE ]]; then
			FUZZ_LDFLAGS="$FUZZ_LDFLAGS -fsanitize=fuzzer-no-link"
		else
			FUZZ_LDFLAGS="$FUZZ_LDFLAGS -fsanitize=fuzzer"
		fi
	fi
fi

rm -f $WORK/*.a $WORK/*.o

# Build and archive necessary Janus objects
JANUS_LIB="$WORK/janus-lib.a"
cd $SRC/$JANUSGW
# Use this variable to skip Janus objects building
SKIP_JANUS_BUILD=${SKIP_JANUS_BUILD-"0"}
if [ "$SKIP_JANUS_BUILD" -eq "0" ]; then
	echo "Building Janus objects"
	./autogen.sh
	./configure CC="$FUZZ_CC" CFLAGS="$FUZZ_CFLAGS" $JANUS_CONF_FLAGS
	make clean
	make -j$(nproc) $JANUS_OBJECTS
fi
ar rcs $JANUS_LIB $JANUS_OBJECTS
cd -

# Build standalone fuzzing engines
engines=$(find $SRC/$JANUSGW/fuzzers/engines/ -name "*.c")
for sourceFile in $engines; do
  name=$(basename $sourceFile .c)
  echo "Building engine: $name"
  $FUZZ_CC -c $FUZZ_CFLAGS $sourceFile -o $WORK/$name.o
done

# Build Fuzzers
mkdir -p $OUT
fuzzers=$(find $SRC/$JANUSGW/fuzzers/ -name "*.c" | grep -v "engines/")
for sourceFile in $fuzzers; do
  name=$(basename $sourceFile .c)
  echo "Building fuzzer: $name"

  $FUZZ_CC -c $FUZZ_CFLAGS $DEPS_CFLAGS -I. -I$SRC/$JANUSGW $sourceFile -o $WORK/$name.o
  $FUZZ_CCLD $FUZZ_LDFLAGS $WORK/${name}.o -o $OUT/${name} $FUZZ_ENGINE $JANUS_LIB $FUZZ_DEPS

  if [ -d "$SRC/$JANUSGW/fuzzers/corpora/${name}" ]; then
	echo "Exporting corpus: $name "
	zip -jqr --exclude=*LICENSE* $OUT/${name}_seed_corpus.zip $SRC/$JANUSGW/fuzzers/corpora/${name}
  fi
done
