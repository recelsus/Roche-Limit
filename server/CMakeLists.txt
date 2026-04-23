find_package(Drogon REQUIRED)

add_executable(roche-limit
    crash_handler.cc
    main.cc
    config/app_config.cc
    http/auth_controller.cc
    http/client_ip_resolver.cc
    http/login_asset_loader.cc
    http/login_controller.cc
    http/login_page_renderer.cc
    http/metrics_controller.cc
    http/request_extractor.cc
    http/request_observability.cc
    http/root_controller.cc
    http/session_cookie_config.cc
)

target_link_libraries(roche-limit
    PRIVATE
        Drogon::Drogon
        roche_limit_common
        roche_limit_auth_core
        roche_limit_auth_store
)

target_include_directories(roche-limit
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(roche-limit
    PRIVATE
        ROCHE_LIMIT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)
