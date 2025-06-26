cmake_minimum_required(VERSION 4.0.3)

#发布模式
set(CMAKE_BUILD_TYPE Release)
#set(CMAKE_BUILD_TYPE Debug)

# 设置C++标准为C++14
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置项目名称
set(PROJECT_NAME "WebToCppConverter") #改成自己的项目名称
project(${PROJECT_NAME} C CXX)

# 检测并配置OpenMP支持
find_package(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OpenMP support found.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif ()

set(COMPILER "x86") #模式选项

if (COMPILER MATCHES "arm64")
    set(CMAKE_HOST_SYSTEM_NAME Linux)
    set(CMAKE_C_COMPILER "/bin/aarch64-linux-gnu-gcc-7")
    set(CMAKE_CXX_COMPILER "/bin/aarch64-linux-gnu-g++-7")
elseif (COMPILER MATCHES "arm32")
    set(CMAKE_HOST_SYSTEM_NAME Linux)
    set(CMAKE_C_COMPILER "/usr/bin/arm-linux-gnueabihf-gcc-7")
    set(CMAKE_CXX_COMPILER "/usr/bin/arm-linux-gnueabihf-g++-7")
    #set(CMAKE_C_COMPILER "/home/lsx/gcc-linaro-5.4.1-2017.05-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc")
    #set(CMAKE_CXX_COMPILER "/home/lsx/gcc-linaro-5.4.1-2017.05-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-g++")
    #set(CMAKE_CXX_LINK_EXECUTABLE "/home/lsx/gcc-linaro-5.4.1-2017.05-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-ld")

    link_directories(${CMAKE_CURRENT_SOURCE_DIR}/TrafficPublic) # 明确路径
    # 新增：显式指定SQLite3静态库路径（避免链接冲突）
    set(TRAFFIC_LIB "${CMAKE_CURRENT_SOURCE_DIR}/TrafficPublic/libTraffic.a")
    set(GENDATA_LIB "${CMAKE_CURRENT_SOURCE_DIR}/TrafficPublic/libgendata.a")
elseif (COMPILER MATCHES "x86")
    set(CMAKE_C_COMPILER "gcc")
    set(CMAKE_CXX_COMPILER "g++")
endif ()

set(PUBLIC_PACKAGE_DIR "/home/lsx/PublicPackage")

# 自动查找所有源文件并添加到目标
file(GLOB_RECURSE SOURCES "${PUBLIC_PACKAGE_DIR}/*.cpp" "${PUBLIC_PACKAGE_DIR}/*.cc" "${PUBLIC_PACKAGE_DIR}/*.c" "${CMAKE_SOURCE_DIR}/*.cpp" "${CMAKE_SOURCE_DIR}/*.cc" "${CMAKE_SOURCE_DIR}/*.c")
# 手动排除构建目录中的生成文件
list(FILTER SOURCES EXCLUDE REGEX "${CMAKE_BINARY_DIR}")
add_executable(${PROJECT_NAME} ${SOURCES})


# 自动查找所有头文件并获取其目录
file(GLOB_RECURSE HEADER_FILES "${PUBLIC_PACKAGE_DIR}/*.h" "${PUBLIC_PACKAGE_DIR}/*.hpp" "${CMAKE_SOURCE_DIR}/*.h" "${CMAKE_SOURCE_DIR}/*.hpp")

# 提取目录路径
set(INCLUDE_DIRS "")
foreach (HEADER_FILE ${HEADER_FILES})
    get_filename_component(DIR_PATH ${HEADER_FILE} DIRECTORY)
    list(APPEND INCLUDE_DIRS ${DIR_PATH})
endforeach ()

# 只保留唯一的目录
list(REMOVE_DUPLICATES INCLUDE_DIRS)

# 添加到目标
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS})

# 链接pthread库
target_link_libraries(${PROJECT_NAME}
        PRIVATE
#        ${TRAFFIC_LIB}  # 必须作为第一个链接库
#        ${GENDATA_LIB}
        pthread
        rt
        dl
        m
        -Wl,--start-group  # 防止循环依赖
        -Wl,--end-group
)

# 新增：强制检查库ABI兼容性
set_target_properties(${PROJECT_NAME} PROPERTIES
        LINK_WHAT_YOU_USE TRUE
)
