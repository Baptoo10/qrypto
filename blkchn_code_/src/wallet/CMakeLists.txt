cmake_minimum_required(VERSION 3.18)
project(wallet)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(wallet
        gen_key.c
        gen_key.h)
