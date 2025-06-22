add_library(aes_encryption_plugin STATIC impl/aes_encryption_plugin.cpp impl/aes_engine.cpp impl/aes_config.cpp)

target_include_directories(aes_encryption_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(aes_encryption_plugin PRIVATE ramulator)

