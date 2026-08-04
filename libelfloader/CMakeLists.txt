cmake_minimum_required(VERSION 3.20)

project(elfloader C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Détection subproject
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(IS_SUBPROJECT TRUE)
else()
  set(IS_SUBPROJECT FALSE)
endif()

# Sources lib uniquement
# - socksrv.c  exclu : a son propre main()
# - bootstrap.c exclu : inclut socksrv_elf.c généré par xxd (build standalone seulement)
# - main.c      exclu : inclut bootstrap_elf.c généré par xxd (build standalone seulement)
set(ELFLOADER_SOURCES
  elfldr.c
  selfldr.c
  notify.c
  pt.c
  uri.c
)

add_library(elfloader STATIC ${ELFLOADER_SOURCES})

target_include_directories(elfloader
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    $ENV{PS5_PAYLOAD_SDK}/include
)

target_compile_options(elfloader PRIVATE
  --target=x86_64-sie-ps5
  -march=znver2
  -DPPR -DPS5
  -DPS5_FW_VERSION=${V_FW}
  -D_POSIX_SOURCE
  -D_POSIX_C_SOURCE=200112
  -D__BSD_VISIBLE=1
  -D__XSI_VISIBLE=500
  -fno-builtin
  -nostdlib
  -fPIC
  -O3
  -Wall
  -Werror
)

set_target_properties(elfloader PROPERTIES
  OUTPUT_NAME "elfloader"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

message(STATUS "[libelfloader] configured (subproject=${IS_SUBPROJECT})")
