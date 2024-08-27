cmake_minimum_required(VERSION 3.5)
project(SecureEmailRegister VERSION 0.1)

# ##############################################################################
# General flags
# ##############################################################################

# We use C++17 in this project because: 1) It's what Chromium supports (see
# https://chromium.googlesource.com/chromium/src/+/HEAD/styleguide/c++/c++.md
# "Modern C++ features") 2) C++17 drastically improved template support in the
# language. Although the code in this codebase is very much "C with classes,
# plus auto" we use templates in one place and it makes life much better.
#
# If this is a deal breaker then we can drop down to C++11.
set(CMAKE_CXX_STANDARD 17)

# This produces a json file that let's you jump into various file definitions
# etc This can be useful if you use VSCode, but it's also useful if you have an
# editor that supports clangd more generally.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-fPIC)
# ##############################################################################
# BoringSSL
# ##############################################################################
add_subdirectory(boringssl)

# SYSTEM here means that the include paths are mapped from "" to <>. This is so
# we can include nested header files in our code.
# Note that this version of BoringSSL is slightly tweaked: we remove some diagnostic flags
# from their CMakeLists to make sure that Clang doesn't complain.
include_directories(SYSTEM "boringssl/include" "boringssl")
enable_testing()

# ##############################################################################
# EmpTool
# ##############################################################################

# N.B Emptool must be configured to use SHA2 instead of SHA-3. This is primarily
# for compatibility with BoringSSL. We use a explicitly modified version for this
# task.
include_directories(SYSTEM "emp/emp-tool" "emp/emp-ot" "emp/emp-ag2pc")
add_subdirectory("emp/emp-tool")
add_subdirectory("emp/emp-ag2pc")

# N.B EmpTool needs a directory to store the pre OT secrets. No idea why -- maybe
# for resumability? Anyway, this makes one in the build directory
file(MAKE_DIRECTORY "build/data")

# ##############################################################################
# DiStefano
# ##############################################################################

add_subdirectory("DiStefano")

# ##############################################################################
# FreeAuth
# ##############################################################################
# set(G_LD_FLAGS "TLSAttestOpt")
# separate_arguments(LD_FLAGS UNIX_COMMAND "${G_LD_FLAGS}")
set(G_C_FLAGS "-g" "-Ofast" "-Wall" "-march=native")
separate_arguments(C_FLAGS UNIX_COMMAND "${G_C_FLAGS}")
include_directories("DiStefano")
add_library(ThreePartyEcrypt STATIC FreeAuth/LibThreePartyEncrypt.cpp)
target_compile_options(ThreePartyEcrypt PRIVATE ${C_FLAGS})

set(EMAILREG_EXES TestSingleCommitVerifier TestSingleCommitProver 
    TestSMTPServer      TestSMTPProver      TestSMTPVerifier)
foreach(EXE ${EMAILREG_EXES})
  add_executable(${EXE} FreeAuth/${EXE}.cpp)
  target_compile_options(${EXE} PRIVATE ${C_FLAGS})
  target_link_Libraries(${EXE} PRIVATE TLSAttestOpt ThreePartyEcrypt TLSAttestOpt)
endforeach(EXE )

add_library(NodeWrapperSMTP SHARED FreeAuth/LibNodeWrapperSMTP.cpp)
target_compile_options(NodeWrapperSMTP PRIVATE ${C_FLAGS})
target_link_Libraries(NodeWrapperSMTP PRIVATE TLSAttestOpt ThreePartyEcrypt TLSAttestOpt)
