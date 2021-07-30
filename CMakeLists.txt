cmake_minimum_required(VERSION 3.19)

# set the project name and version
project(janus_gateway VERSION 0.11.4 LANGUAGES C)
string(TOLOWER "${PROJECT_NAME}" PROJECT_LOWER_NAME)

set(CMAKE_C_STANDARD 90)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_library("${PROJECT_LOWER_NAME}_compiler_flags" INTERFACE)
target_compile_features("${PROJECT_LOWER_NAME}_compiler_flags" INTERFACE "c_std_90")

# add compiler warning flags just when building this project via
# the BUILD_INTERFACE genex
set(gcc_like "$<COMPILE_LANG_AND_ID:C,CXX,ARMClang,AppleClang,Clang,GNU>")
set(msvc "$<COMPILE_LANG_AND_ID:C,CXX,MSVC>")
target_compile_options(
        "${PROJECT_LOWER_NAME}_compiler_flags"
        INTERFACE
        "$<${gcc_like}:$<BUILD_INTERFACE:-Wshadow;-Wformat=2;
        -fPIC;
	-fstack-protector-all;
	-fstrict-aliasing;
	-ggdb3;
	-pthread;
	-Wall;
	-Warray-bounds;
	-Wextra;
	-Wformat-nonliteral;
	-Wformat-security;
	-Wformat=2;
	-Winit-self;
	-Winline;
	-Wlarger-than=65537;
	-Wmissing-declarations;
	-Wmissing-format-attribute;
	-Wmissing-include-dirs;
	-Wmissing-noreturn;
	-Wmissing-prototypes;
	-Wnested-externs;
	-Wno-aggregate-return;
	-Wno-missing-field-initializers;
	-Wno-redundant-decls;
	-Wno-undef;
	-Wno-unused-parameter;
	-Wold-style-definition;
	-Wpacked;
	-Wpointer-arith;
	-Wsign-compare;
	-Wstrict-prototypes;
	-Wswitch-default;
	-Wunused;
	-Wwrite-strings;
	-Werror=implicit-function-declaration
        >>"
        "$<${msvc}:$<BUILD_INTERFACE:-W3;-WX;-Zi;-permissive->>"
)
if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    add_compile_options("-Wno-cast-align;-Wno-initializer-overrides")
elseif (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options("-Wcast-align;-Wno-override-init;-Wunsafe-loop-optimizations;-Wunused-but-set-variable")
else() # `cc` (same as Clang?)
    add_compile_options("-Wno-cast-align;-Wno-initializer-overrides")
endif()

if(APPLE)
    add_link_options(-Wl;-export_dynamic)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    add_link_options(-Xlinker;--export-dynamic)
else()
    add_link_options(-Wl;--export-dynamic)
endif()

# control where the static and shared libraries are built so that on windows
# we don't need to tinker with the path to run the executable
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if(APPLE)
    set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
elseif(UNIX)
    set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()

# configure a header file to pass the version number only
configure_file(
        "${PROJECT_NAME}Config.h.in"
        "${PROJECT_NAME}Config.h"
)

set(original_deps "src" # "events" "fuzzers" "loggers" "plugins" "postprocessing" "transports"
        )
foreach (_lib ${original_deps})
    add_subdirectory("${_lib}")
    message(STATUS "Built ${_lib}")
endforeach ()

set_target_properties(
        "${PROJECT_NAME}"
        PROPERTIES
        LINKER_LANGUAGE
        C
)

# add the binary tree to the search path for include files
# so that we will find "${PROJECT_NAME}Config.h"
target_include_directories(
        "${PROJECT_NAME}"
        PUBLIC
        "${PROJECT_BINARY_DIR}"
)
