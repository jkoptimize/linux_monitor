cmake_minimum_required(VERSION 3.15)
project(plain_monitor)

# 通过选项控制是否生成共享库
option(BUILD_SHARED_LIB "Build shared library" OFF)

function(build_library name)
    if(BUILD_SHARED_LIB)
        add_library(${name} SHARED ${ARGN})
        message(STATUS "Building shared library: ${name}")
    else()
        add_executable(${name} ${ARGN})
        message(STATUS "Building executable: ${name}")
    endif()
    
    # 设置头文件路径
    target_include_directories(${name} 
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_options(${name} PRIVATE
        -O0 -g
    )
endfunction()

set(MEM_MONITOR_SOURCES
    mem_monitor.c
)
set(DISK_MONITOR_SOURCES
    disk_monitor.c
)
set(CPU_LOAD_MONITOR_SOURCES
    cpu_load_monitor.c
)

if(NOT BUILD_SHARED_LIB)
    list(APPEND MEM_MONITOR_SOURCES  mem_monitor_main.c)
    list(APPEND DISK_MONITOR_SOURCES disk_monitor_main.c)
    list(APPEND CPU_LOAD_MONITOR_SOURCES cpu_load_monitor_main.c)
endif()

build_library(cpu_load_monitor ${CPU_LOAD_MONITOR_SOURCES})
build_library(disk_monitor ${DISK_MONITOR_SOURCES})
build_library(mem_monitor ${MEM_MONITOR_SOURCES})

# # 获取内核版本
# execute_process(COMMAND uname -r
#     OUTPUT_VARIABLE KERNEL_VERSION
#     OUTPUT_STRIP_TRAILING_WHITESPACE
# )

# # 定义内核模块的构建目标
# set(KERNEL_MODULES
#     cpu_stat_monitor_kmod
# )

# # 定义内核模块的构建目标
# set(MODULE_TARGETS)
# foreach(MODULE ${KERNEL_MODULES})
#     add_custom_target(${MODULE}_module
#         COMMAND make -C /lib/modules/${KERNEL_VERSION}/build M=${CMAKE_CURRENT_SOURCE_DIR} modules
#         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#         COMMENT "Building kernel module: ${MODULE}"
#     )
#     list(APPEND MODULE_TARGETS ${MODULE}_module)
# endforeach()

# # 定义所有内核模块的构建目标
# add_custom_target(modules ALL DEPENDS ${MODULE_TARGETS})


set(CUSTOM_KERNEL_DIR "/root/WSL2-Linux-Kernel-linux-msft-wsl-6.6.87.2")

# 定义内核模块的构建目标
set(KERNEL_MODULES cpu_stat_monitor_kmod)

set(MODULE_TARGETS)
foreach(MODULE ${KERNEL_MODULES})
    add_custom_target(${MODULE}_module
        COMMAND make -C ${CUSTOM_KERNEL_DIR} M=${CMAKE_CURRENT_SOURCE_DIR} modules
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building kernel module: ${MODULE} using custom kernel headers"
    )
    list(APPEND MODULE_TARGETS ${MODULE}_module)
endforeach()

add_custom_target(modules ALL DEPENDS ${MODULE_TARGETS})