find_package(Drogon REQUIRED)

add_executable(roche-limit
    main.cc
    config/app_config.cc
    http/auth_controller.cc
    http/request_extractor.cc
    http/root_controller.cc
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
