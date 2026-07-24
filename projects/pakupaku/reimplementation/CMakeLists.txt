cmake_minimum_required(VERSION 3.16)
project(pakupaku_reimplementation VERSION 0.1.0 LANGUAGES CXX)

option(PAKUPAKU_BUILD_TESTS "Build synthetic unit tests" ON)

add_library(
    pakupaku_core
    src/assets.cpp
    src/game.cpp
    src/presenter.cpp
    src/renderer.cpp
    src/sha256.cpp
)
target_include_directories(pakupaku_core PUBLIC include)
target_compile_features(pakupaku_core PUBLIC cxx_std_17)

if(MSVC)
    target_compile_options(pakupaku_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(pakupaku_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(pakupaku src/game_main.cpp)
target_link_libraries(pakupaku PRIVATE pakupaku_core)

if(WIN32)
    add_executable(pakupaku_play src/interactive_win32.cpp)
    target_link_libraries(pakupaku_play PRIVATE pakupaku_core user32 gdi32)
    if(MSVC)
        target_compile_options(pakupaku_play PRIVATE /W4 /permissive-)
    endif()
endif()

if(PAKUPAKU_BUILD_TESTS)
    enable_testing()
    add_executable(pakupaku_tests tests/core_tests.cpp)
    target_link_libraries(pakupaku_tests PRIVATE pakupaku_core)
    add_test(NAME pakupaku_core_tests COMMAND pakupaku_tests)
    add_executable(pakupaku_game_tests tests/game_tests.cpp)
    target_link_libraries(pakupaku_game_tests PRIVATE pakupaku_core)
    add_test(NAME pakupaku_game_tests COMMAND pakupaku_game_tests)
endif()
