cmake_minimum_required(VERSION 3.20)
project(TrayApp VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "TrayApp is a Windows-only Win32 application.")
endif()

add_executable(TrayApp WIN32 src/main.cpp)
target_compile_features(TrayApp PRIVATE cxx_std_17)
target_compile_definitions(TrayApp PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(TrayApp PRIVATE user32 shell32 advapi32)

if(MSVC)
    target_compile_options(TrayApp PRIVATE /W4 /utf-8)
endif()

set_target_properties(TrayApp PROPERTIES
    OUTPUT_NAME "TrayApp"
    WIN32_EXECUTABLE TRUE
)
