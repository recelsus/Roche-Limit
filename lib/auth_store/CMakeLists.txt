find_package(SQLite3 REQUIRED)

add_library(roche_limit_auth_store
    src/audit_repository.cc
    src/rule_repository.cc
    src/rule_repository_api_key.cc
    src/rule_repository_compact.cc
    src/schema_bootstrap.cc
    src/sqlite_connection.cc
    src/user_repository.cc
    src/user_repository_compact.cc
    src/user_repository_csrf.cc
    src/user_repository_login_failure.cc
    src/user_repository_session.cc
)

target_include_directories(roche_limit_auth_store
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(TARGET SQLite3::SQLite3)
    set(ROCHE_LIMIT_SQLITE_LINK_TARGET SQLite3::SQLite3)
else()
    set(ROCHE_LIMIT_SQLITE_LINK_TARGET ${SQLite3_LIBRARIES})
    target_include_directories(roche_limit_auth_store
        PUBLIC
            ${SQLite3_INCLUDE_DIRS}
    )
endif()

target_link_libraries(roche_limit_auth_store
    PUBLIC
        ${ROCHE_LIMIT_SQLITE_LINK_TARGET}
        roche_limit_auth_core
        roche_limit_common
)

target_compile_definitions(roche_limit_auth_store
    PRIVATE
        ROCHE_LIMIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)
