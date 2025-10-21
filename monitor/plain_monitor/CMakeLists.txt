cmake_minimum_required(VERSION 3.15)
project(plain_monitor)

# 1. 选项：控制是否构建共享库
option(BUILD_SHARED_LIB "Build shared library" OFF)

# 2. 用户态程序构建函数
function(build_library name)
    if(BUILD_SHARED_LIB)
        add_library(${name} SHARED ${ARGN})
        message(STATUS "Building shared library: ${name}")
    else()
        add_executable(${name} ${ARGN})
        message(STATUS "Building executable: ${name}")
        set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()

    target_include_directories(${name} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(${name} PRIVATE -O0 -g)
endfunction()

# 3. 用户态程序源文件
set(CPU_LOAD_MONITOR_SOURCES cpu_load_monitor.c)
set(DISK_MONITOR_SOURCES disk_monitor.c)
set(MEM_MONITOR_SOURCES mem_monitor.c)

if(NOT BUILD_SHARED_LIB)
    list(APPEND CPU_LOAD_MONITOR_SOURCES cpu_load_monitor_main.c)
    list(APPEND DISK_MONITOR_SOURCES disk_monitor_main.c)
    list(APPEND MEM_MONITOR_SOURCES mem_monitor_main.c)
endif()

# 4. 构建用户态程序
build_library(cpu_load_monitor ${CPU_LOAD_MONITOR_SOURCES})
build_library(disk_monitor ${DISK_MONITOR_SOURCES})
build_library(mem_monitor ${MEM_MONITOR_SOURCES})




# 添加内核模块的构建逻辑
set(KERNEL_MODULES
    cpu_stat_monitor_kmod
)
set(CUSTOM_KERNEL_DIR "/root/WSL2-Linux-Kernel-linux-msft-wsl-6.6.87.2")

# 定义内核模块的构建目标
set(MODULE_TARGETS)
foreach(MODULE ${KERNEL_MODULES})
    add_custom_target(${MODULE}_module
        COMMAND make -C ${CUSTOM_KERNEL_DIR} M=${CMAKE_CURRENT_SOURCE_DIR} modules INSTALL_MOD_PATH=${CMAKE_CURRENT_SOURCE_DIR}/build
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building kernel module: ${MODULE}"
    )
    list(APPEND MODULE_TARGETS ${MODULE}_module)
endforeach()

# 定义所有内核模块的构建目标
add_custom_target(modules ALL DEPENDS ${MODULE_TARGETS})








# # 5. 内核模块构建（关键：直接输出到 CMAKE_BINARY_DIR）
# set(KERNEL_MODULES cpu_stat_monitor_kmod)
# set(CUSTOM_KERNEL_DIR "/root/WSL2-Linux-Kernel-linux-msft-wsl-6.6.87.2")

# # 6. 创建内核模块构建所需的临时目录（在构建目录下）
# set(KMOD_BUILD_DIR ${CMAKE_BINARY_DIR}/kmod_src)
# file(MAKE_DIRECTORY ${KMOD_BUILD_DIR})

# # 9. 定义内核模块构建目标（直接输出到构建目录根）
# set(MODULE_TARGETS)
# foreach(MODULE ${KERNEL_MODULES})
#     add_custom_target(${MODULE}_module ALL
#         COMMAND make -C ${CUSTOM_KERNEL_DIR} M=${KMOD_BUILD_DIR} modules
#         WORKING_DIRECTORY ${KMOD_BUILD_DIR}
#         COMMENT "Building kernel module: ${MODULE} (output to ${CMAKE_BINARY_DIR})"
#         VERBATIM
#     )
#     list(APPEND MODULE_TARGETS ${MODULE}_module)
# endforeach()

# # 10. 定义总目标
# add_custom_target(modules ALL DEPENDS ${MODULE_TARGETS})