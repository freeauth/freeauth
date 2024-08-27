set(emp-tool_DIR ../emp-tool/cmake)
# find_package(emp-tool)

find_path(EMP-OT_INCLUDE_DIR emp-ot/emp-ot.h PATHS ${CMAKE_SOURCE_DIR}/emp/emp-ot)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(emp-ot DEFAULT_MSG EMP-OT_INCLUDE_DIR)

if(EMP-OT_FOUND)
	set(EMP-OT_INCLUDE_DIRS ${EMP-TOOL_INCLUDE_DIRS} ${EMP-OT_INCLUDE_DIR})
	set(EMP-OT_LIBRARIES ${EMP-TOOL_LIBRARIES} emp-tool ssl)
endif()
