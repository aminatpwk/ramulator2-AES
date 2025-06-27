add_library(aes_encryption_plugin MODULE impl/aes_encryption_plugin.cpp impl/aes_engine.cpp impl/aes_config.cpp)

set_target_properties(aes_encryption_plugin PROPERTIES
        OUTPUT_NAME "aes_encryption"
        PREFIX ""
        SUFFIX ".so"
)

target_include_directories(aes_encryption_plugin PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(aes_encryption_plugin PUBLIC ramulator)

message(STATUS "Plugin will be built at: ${CMAKE_CURRENT_BINARY_DIR}/aes_encryption.so")
