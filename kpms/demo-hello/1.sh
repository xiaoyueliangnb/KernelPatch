#!/bin/bash

set -e

CURRENT_USER=$(whoami)
ANDROID_NDK="/home/$CURRENT_USER/Android/Sdk/ndk/ndk-r27/ndk"

# 构建目录
BUILD_DIR=build
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# 配置 CMake
cmake ..

# 构建
cmake --build .

echo "构建完成，生成文件在 build/hello.kpm"
