cmake_minimum_required(VERSION 3.24)
project(OpenStudentDefender)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")

add_executable(OpenStudentDefender main.cpp)
target_link_libraries(OpenStudentDefender pthread)
