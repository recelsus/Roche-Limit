cmake_minimum_required(VERSION 3.16)
project(roche_limit VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)

add_subdirectory(lib/common)
add_subdirectory(lib/auth_core)
add_subdirectory(lib/auth_store)
add_subdirectory(server)
add_subdirectory(tools)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

set(LINK_COMPILE_COMMANDS_SCRIPT ${CMAKE_BINARY_DIR}/link_compile_commands.cmake)
file(WRITE ${LINK_COMPILE_COMMANDS_SCRIPT}
    "if(EXISTS \"${CMAKE_BINARY_DIR}/compile_commands.json\")\n"
    "  if(WIN32)\n"
    "    file(COPY \"${CMAKE_BINARY_DIR}/compile_commands.json\" DESTINATION \"${CMAKE_SOURCE_DIR}\")\n"
    "  else()\n"
    "    file(REMOVE \"${CMAKE_SOURCE_DIR}/compile_commands.json\")\n"
    "    file(CREATE_LINK \"${CMAKE_BINARY_DIR}/compile_commands.json\" \"${CMAKE_SOURCE_DIR}/compile_commands.json\" SYMBOLIC)\n"
    "  endif()\n"
    "endif()\n"
)

add_custom_target(link_compile_commands ALL
    COMMAND ${CMAKE_COMMAND} -P ${LINK_COMPILE_COMMANDS_SCRIPT}
    COMMENT "Update compile_commands.json within the project root"
)
