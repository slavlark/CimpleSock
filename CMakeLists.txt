cmake_minimum_required(VERSION 4.2)
project(CimpleSock C)

set(CMAKE_C_STANDARD 99)

add_library(CimpleSock STATIC cimplesock.h
        cimplesock_server.h
        cimplesock_server.c)