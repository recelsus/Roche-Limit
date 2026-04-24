add_executable(roche_limit_cli
    audit_command.cc
    audit_logging.cc
    cli_support.cc
    ip_command.cc
    key_command.cc
    main.cc
    user_command.cc
)

target_link_libraries(roche_limit_cli
    PRIVATE
        roche_limit_common
        roche_limit_auth_core
        roche_limit_auth_store
)

target_include_directories(roche_limit_cli
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)
