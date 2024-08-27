project (emp-ag2pc VERSION 0.1)
set(NAME "emp-ag2pc")

set(CMAKE_FOLDER ../emp-tool)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
set(emp-ot_DIR ../emp-ot/cmake)
FIND_PACKAGE(emp-ot REQUIRED)
INCLUDE_DIRECTORIES(${EMP-OT_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-ag2pc-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ag2pc DESTINATION include)

# ENABLE_TESTING()
# ADD_SUBDIRECTORY(test)
