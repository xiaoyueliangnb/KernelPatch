#!/bin/bash

CURRENT_USER=$(whoami)

echo "Current user: $CURRENT_USER"

# 检查 ANDROID_NDK 是否已设置
export ANDROID_NDK=/home/$CURRENT_USER/Android/Sdk/ndk/ndk-r27/ndk

# 设置其他环境变量
export ANDROID=1

# 设置构建选项
BUILD_DIR=build
CMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
CMAKE_BUILD_TYPE=Release
ANDROID_PLATFORM=android-34
ANDROID_ABI=arm64-v8a

# 创建构建目录并进入该目录
mkdir -p $BUILD_DIR && cd $BUILD_DIR

# 运行 CMake 配置命令
cmake -DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE \
      -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE \
      -DANDROID_PLATFORM=$ANDROID_PLATFORM \
      -DANDROID_ABI=$ANDROID_ABI ../

# 检查 CMake 配置是否成功
if [ $? -ne 0 ]; then
  echo "CMake 配置失败"
  exit 1
fi

# 构建项目
cmake --build .

# 检查构建是否成功
if [ $? -ne 0 ]; then
  echo "构建失败"
  exit 1
fi

echo "构建成功"
