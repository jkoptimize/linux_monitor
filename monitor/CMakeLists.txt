cmake_minimum_required(VERSION 3.10)
project(monitor)

# 构建 plain_monitor（使用 add_subdirectory）
add_subdirectory(plain_monitor)

# 构建 ebpf（使用 make）
add_custom_target(ebpf_build
    COMMAND ${CMAKE_MAKE_PROGRAM} -C ${CMAKE_CURRENT_SOURCE_DIR}/ebpf
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ebpf
    COMMENT "Building ebpf module with make..."
    VERBATIM
)

# 可选：创建一个统一的 target 来一键构建全部
add_custom_target(all_build
    DEPENDS plain_monitor ebpf_build
    COMMENT "Building all components: plain_monitor and ebpf"
)