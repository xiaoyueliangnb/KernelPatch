cmake_minimum_required(VERSION 3.10)
project(demo_hello_kpm C)

# 指向 NDK clang
set(ANDROID_NDK "/home/$ENV{USER}/Android/Sdk/ndk/ndk-r27/ndk")
set(CMAKE_C_COMPILER "${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang")

# 内核头路径
set(KP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
include_directories(
    "${KP_DIR}/kernel/."
    "${KP_DIR}/kernel/include"
    "${KP_DIR}/kernel/patch/include"
    "${KP_DIR}/kernel/linux/include"
    "${KP_DIR}/kernel/linux/arch/arm64/include"
    "${KP_DIR}/kernel/linux/tools/arch/arm64/include"
)

# 源文件
set(SOURCES hello.c)

# OBJECT 库
add_library(hello_obj OBJECT ${SOURCES})

# 用 target_compile_options 传递参数列表，而不是 COMPILE_FLAGS
target_compile_options(hello_obj PRIVATE
    -ffreestanding
    -fno-builtin
    -fno-pic
    -fno-plt
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -fno-exceptions
    -fno-omit-frame-pointer
    -D__KERNEL__
    -DMODULE
    -O2
    -Thello.lds
)

# clang -r 生成 hello.kpm
add_custom_command(
    OUTPUT hello.kpm
    COMMAND ${CMAKE_C_COMPILER} -r $<TARGET_OBJECTS:hello_obj> -o hello.kpm
    DEPENDS hello_obj
)

add_custom_target(hello ALL DEPENDS hello.kpm)

# 清理
add_custom_target(distclean
    COMMAND ${CMAKE_COMMAND} -E rm -f hello.kpm
    COMMAND ${CMAKE_COMMAND} -E rm -f ${CMAKE_CURRENT_BINARY_DIR}/*.o
)
