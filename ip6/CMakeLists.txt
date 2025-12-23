cmake_minimum_required(VERSION 3.10)
project(ip6 LANGUAGES C VERSION 0.1.0)

add_compile_options(-march=haswell)
add_executable(hash hash.c)
add_executable(perm perm.c)
add_executable(ip6 ip6.c)
