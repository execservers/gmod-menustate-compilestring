cmake_minimum_required(VERSION 3.21)
project(gmod_menustate_compilestring LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "This injectable DLL requires Windows with MSVC (Win32 or x64).")
endif()

option(MENUSTATE_COMPILESTRING_STDOUT "Build a _stdout_ DLL with asynchronous CompileString logging" OFF)

include(FetchContent)
# Can be overridden with -DFETCHCONTENT_SOURCE_DIR_GARRYSMOD_COMMON=...
# For fully reproducible builds, replace 'master' with a reviewed commit SHA.
FetchContent_Declare(garrysmod_common
    GIT_REPOSITORY https://github.com/danielga/garrysmod_common.git
    GIT_TAG master
    GIT_SHALLOW TRUE
    GIT_SUBMODULES ""
)
FetchContent_MakeAvailable(garrysmod_common)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(BITS 32)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BITS 64)
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()

add_library(menustate_compilestring SHARED src/menustate_compilestring.cpp)
target_include_directories(menustate_compilestring PRIVATE "${garrysmod_common_SOURCE_DIR}/include")
target_compile_features(menustate_compilestring PRIVATE cxx_std_17)
target_compile_definitions(menustate_compilestring PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(menustate_compilestring PRIVATE /W4 /EHsc /permissive-)
set_property(TARGET menustate_compilestring PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(MENUSTATE_COMPILESTRING_STDOUT)
    target_sources(menustate_compilestring PRIVATE src/stdout_console.cpp)
    target_compile_definitions(menustate_compilestring PRIVATE MENUSTATE_COMPILESTRING_STDOUT=1)
    set(DLL_NAME "menustate_compilestring_stdout_win${BITS}")
else()
    set(DLL_NAME "menustate_compilestring_win${BITS}")
endif()

set_target_properties(menustate_compilestring PROPERTIES
    PREFIX ""
    OUTPUT_NAME "${DLL_NAME}"
)
target_link_libraries(menustate_compilestring PRIVATE user32)
