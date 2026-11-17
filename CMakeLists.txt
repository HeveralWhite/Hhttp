cmake_minimum_required(VERSION 3.16)
project(Hhttp VERSION 1.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------
# 构建类型 / 优化级别
# ---------------------------------------------------------------
# 本项目是"QuickJS 解释执行 + HTTP 文本解析"型负载,对编译优化非常敏感:
# Debug(-O0) 产物的吞吐通常比 -O2 低数倍,高并发下表现为"性能开销过大"。
# 因此: 未显式指定构建类型时,默认使用 Release。

# 默认构建类型(想整体换默认值时: -DHHTTP_DEFAULT_BUILD_TYPE=RelWithDebInfo)
set(HHTTP_DEFAULT_BUILD_TYPE "Release" CACHE STRING
    "未显式指定构建类型时使用的默认值")

# 单配置生成器(Ninja / MinGW Makefiles / Unix Makefiles)会把 CMAKE_BUILD_TYPE
# 持久化进 CMakeCache.txt。只要缓存里是 Debug,后面的配置即使不传任何参数也仍是
# Debug,旧的 if(NOT CMAKE_BUILD_TYPE) 分支永远不会执行 —— 这就是
# "改成了默认 Release,但每次编译仍然是 Debug" 的真正原因(默认值被构建缓存劫持)。
#
# 这里引入 HHTTP_BUILD_TYPE_MANAGED 记录"缓存值是不是本项目自动写入的默认值":
#   托管(=ON ,用户没显式选过)      -> 允许跟随 HHTTP_DEFAULT_BUILD_TYPE 升级
#   非托管(=OFF,用户显式选过 Debug)-> 永远尊重用户选择,不做任何覆盖
if(NOT CMAKE_CONFIGURATION_TYPES)
    if(NOT CMAKE_BUILD_TYPE)
        # 全新构建目录(缓存里没有值):直接写默认值
        set(CMAKE_BUILD_TYPE "${HHTTP_DEFAULT_BUILD_TYPE}" CACHE STRING "Build type" FORCE)
    elseif(HHTTP_BUILD_TYPE_MANAGED AND NOT CMAKE_BUILD_TYPE STREQUAL HHTTP_DEFAULT_BUILD_TYPE)
        # 缓存值是上次由本项目写入的默认值,现在默认值变了 -> 平滑跟随
        message(STATUS "Hhttp: migrate build type ${CMAKE_BUILD_TYPE} -> ${HHTTP_DEFAULT_BUILD_TYPE}")
        set(CMAKE_BUILD_TYPE "${HHTTP_DEFAULT_BUILD_TYPE}" CACHE STRING "Build type" FORCE)
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL HHTTP_DEFAULT_BUILD_TYPE)
        set(HHTTP_BUILD_TYPE_MANAGED ON CACHE INTERNAL "缓存值由本项目默认值写入")
    else()
        set(HHTTP_BUILD_TYPE_MANAGED OFF CACHE INTERNAL "用户显式指定的构建类型")
    endif()
else()
    # 多配置生成器(Visual Studio / Ninja Multi-Config):
    # cmake --build 不带 --config 时默认取 CMAKE_CONFIGURATION_TYPES 的第一项,
    # 而它的默认顺序是 Debug 打头 —— 这也是一类"总是 Debug"的成因,故把 Release 提到首位。
    set(CMAKE_CONFIGURATION_TYPES "Release;RelWithDebInfo;MinSizeRel;Debug"
        CACHE STRING "Available build configurations" FORCE)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30)
        set(CMAKE_DEFAULT_BUILD_TYPE "${HHTTP_DEFAULT_BUILD_TYPE}" CACHE STRING
            "多配置生成器的默认构建配置")
    endif()
endif()

# Release 统一收敛到 -O2(GCC / Clang 的默认值是 "-O3 -DNDEBUG"):
# 缩短编译时间,并避开 -O3 的代码膨胀对内联与缓存局部性的负作用。
# 需要其他级别时,配置阶段用 -DCMAKE_CXX_FLAGS_RELEASE=... 覆盖即可。
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"
   AND CMAKE_BUILD_TYPE STREQUAL "Release"
   AND CMAKE_CXX_FLAGS_RELEASE MATCHES "^-O3( |$)")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING
        "Release build flags" FORCE)
endif()

# 把最终生效的构建类型与优化选项打印出来,避免"改了却没生效"的误判
# (控制台输出统一用 ASCII: Windows 控制台默认 cp936,输出中文会乱码)
if(CMAKE_BUILD_TYPE)
    string(TOUPPER "${CMAKE_BUILD_TYPE}" HHTTP_BUILD_TYPE)
    message(STATUS "Hhttp: build type = ${CMAKE_BUILD_TYPE}")
    message(STATUS "Hhttp: optimization flags = ${CMAKE_CXX_FLAGS_${HHTTP_BUILD_TYPE}}")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING
            "Hhttp: Debug (-O0) build detected; use Release for benchmarking")
    elseif(NOT CMAKE_BUILD_TYPE STREQUAL HHTTP_DEFAULT_BUILD_TYPE)
        # 缓存值与项目默认值不同且不是本项目写入的:说明用户显式选过,只提示不改动
        message(STATUS
            "Hhttp: cached build type is ${CMAKE_BUILD_TYPE} (default is ${HHTTP_DEFAULT_BUILD_TYPE}); "
            "use -DCMAKE_BUILD_TYPE=${HHTTP_DEFAULT_BUILD_TYPE} to switch back")
    endif()
else()
    message(STATUS "Hhttp: multi-config generator; build with --config ${HHTTP_DEFAULT_BUILD_TYPE}")
endif()

# ---------------------------------------------------------------
# 源码
# ---------------------------------------------------------------
add_executable(Hhttp
    src/main.cpp
    src/Log.cpp
    src/Log.h
    src/TCP.cpp
    src/TCP.h
    src/TLS.cpp
    src/TLS.h
    src/HTTP.cpp
    src/HTTP.h
    src/WebSocket.cpp
    src/WebSocket.h
    src/JS.h
    src/JS.cpp)

# 仓库内自带的单头文件依赖(nlohmann/json)
target_include_directories(Hhttp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# ---------------------------------------------------------------
# 第三方依赖
# ---------------------------------------------------------------
# 四个依赖都可以用 -D 指向本机解压/编译好的目录(目录内需含 include/ 与 lib/);
# 不指定或目录不存在时自动回退到 find_package / find_path。

set(HHTTP_BOOST_DIR "" CACHE PATH "Boost 源码根目录(含 boost/asio.hpp)")
set(HHTTP_OPENSSL_DIR "" CACHE PATH "OpenSSL 安装目录(含 include/ 与 lib/)")
set(HHTTP_QUICKJS_DIR "" CACHE PATH "QuickJS 目录(含 include/ 与 lib/)")
set(HHTTP_SQLITE3_DIR "" CACHE PATH "SQLite3 目录(含 include/ 与 lib/)")

# Boost:只用头文件(Boost.Asio + Boost.System),不需要编译库
if(HHTTP_BOOST_DIR AND EXISTS "${HHTTP_BOOST_DIR}/boost/asio.hpp")
    target_include_directories(Hhttp PRIVATE ${HHTTP_BOOST_DIR})
else()
    find_package(Boost 1.74 REQUIRED)
    target_include_directories(Hhttp PRIVATE ${Boost_INCLUDE_DIRS})
endif()

find_package(Threads REQUIRED)
target_link_libraries(Hhttp PRIVATE Threads::Threads)

if(HHTTP_QUICKJS_DIR AND EXISTS "${HHTTP_QUICKJS_DIR}/include/quickjs.h")
    target_include_directories(Hhttp PRIVATE ${HHTTP_QUICKJS_DIR}/include)
    target_link_directories(Hhttp PRIVATE ${HHTTP_QUICKJS_DIR}/lib)
    target_link_libraries(Hhttp PRIVATE quickjs)
else()
    # 系统里装好的 quickjs(或 -DQUICKJS_INCLUDE_DIR / -DQUICKJS_LIBRARY 显式指定)
    find_path(QUICKJS_INCLUDE_DIR quickjs.h)
    find_library(QUICKJS_LIBRARY NAMES quickjs quickjs-ng)
    if(NOT QUICKJS_INCLUDE_DIR OR NOT QUICKJS_LIBRARY)
        message(FATAL_ERROR
            "QuickJS not found.\n"
            "  Install it system-wide, or configure with\n"
            "  -DHHTTP_QUICKJS_DIR=<dir containing include/quickjs.h and lib/libquickjs.a>,\n"
            "  or -DQUICKJS_INCLUDE_DIR=<dir> -DQUICKJS_LIBRARY=<path to libquickjs.a>.\n"
            "  Build QuickJS from https://github.com/quickjs-ng/quickjs (or bellard.org/quickjs).")
    endif()
    target_include_directories(Hhttp PRIVATE ${QUICKJS_INCLUDE_DIR})
    target_link_libraries(Hhttp PRIVATE ${QUICKJS_LIBRARY})
endif()

if(HHTTP_SQLITE3_DIR AND EXISTS "${HHTTP_SQLITE3_DIR}/include/sqlite3.h")
    target_include_directories(Hhttp PRIVATE ${HHTTP_SQLITE3_DIR}/include)
    target_link_directories(Hhttp PRIVATE ${HHTTP_SQLITE3_DIR}/lib)
    target_link_libraries(Hhttp PRIVATE sqlite3)
else()
    find_package(SQLite3 REQUIRED)
    target_link_libraries(Hhttp PRIVATE SQLite::SQLite3)
endif()

# OpenSSL 优先使用静态库(libssl.a / libcrypto.a):保持"单个 exe、不需要附带 DLL"的
# 发布方式;需要动态链接时把下面两行换成 -lssl -lcrypto 即可。
set(HHTTP_OPENSSL_LINKED OFF)
if(HHTTP_OPENSSL_DIR AND EXISTS "${HHTTP_OPENSSL_DIR}/lib/libssl.a")
    # Windows / 自编译 OpenSSL:直接链静态库
    target_include_directories(Hhttp PRIVATE ${HHTTP_OPENSSL_DIR}/include)
    target_link_libraries(Hhttp PRIVATE
        "${HHTTP_OPENSSL_DIR}/lib/libssl.a"
        "${HHTTP_OPENSSL_DIR}/lib/libcrypto.a")
    set(HHTTP_OPENSSL_LINKED ON)
elseif(HHTTP_OPENSSL_DIR AND EXISTS "${HHTTP_OPENSSL_DIR}/lib/libssl.dll.a")
    # MSYS2 / MinGW 的动态库:链接 import library 并把 DLL 复制到产物目录
    target_include_directories(Hhttp PRIVATE ${HHTTP_OPENSSL_DIR}/include)
    target_link_directories(Hhttp PRIVATE ${HHTTP_OPENSSL_DIR}/lib)
    target_link_libraries(Hhttp PRIVATE ssl crypto)
    add_custom_command(TARGET Hhttp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${HHTTP_OPENSSL_DIR}/bin/libssl-3-x64.dll"
                "${HHTTP_OPENSSL_DIR}/bin/libcrypto-3-x64.dll"
                "$<TARGET_FILE_DIR:Hhttp>")
    set(HHTTP_OPENSSL_LINKED ON)
endif()

if(NOT HHTTP_OPENSSL_LINKED)
    # Linux / macOS / vcpkg:用系统或包管理器提供的 OpenSSL
    find_package(OpenSSL REQUIRED)
    target_link_libraries(Hhttp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

if(WIN32)
    # Boost.Asio 在 Windows 上用 IOCP(需要 ws2_32 + mswsock);
    # OpenSSL 静态库要用到 crypt32 / advapi32 / user32
    target_link_libraries(Hhttp PRIVATE
        ws2_32
        mswsock
        crypt32
        advapi32
        user32)
endif()

if(MINGW)
    # MinGW 运行时全部静态链接:产物是单个 exe,不依赖任何 MinGW DLL
    target_link_libraries(Hhttp PRIVATE
        atomic
        winpthread   # MinGW 的 pthread 实现
        mingw32      # MinGW 基本库
        gcc)
    target_link_options(Hhttp PRIVATE -static)
elseif(NOT WIN32)
    # POSIX:线程 + dl(部分平台 Asio 需要)
    target_compile_options(Hhttp PRIVATE -pthread)
    target_link_libraries(Hhttp PRIVATE ${CMAKE_DL_LIBS})
endif()
