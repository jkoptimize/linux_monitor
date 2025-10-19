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