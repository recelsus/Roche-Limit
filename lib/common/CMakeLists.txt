find_package(OpenSSL REQUIRED)

add_library(roche_limit_common
    src/hash_util.cc
)

target_include_directories(roche_limit_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(roche_limit_common
    PUBLIC
        OpenSSL::Crypto
)
