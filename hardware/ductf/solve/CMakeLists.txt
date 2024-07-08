cmake_minimum_required(VERSION 3.13)

set(PICO_SDK_FETCH_FROM_GIT on)
set(PICO_EXTRAS_FETCH_FROM_GIT on)

include(pico_sdk_import.cmake)

project(ductf)

pico_sdk_init()

add_executable(solve solve.c bbspi.c)
pico_enable_stdio_uart(solve 1)
pico_enable_stdio_usb(solve 0)

target_link_libraries(solve pico_stdlib hardware_spi)
target_include_directories(solve PRIVATE ${CMAKE_CURRENT_LIST_DIR})



# create map/bin/hex file etc.
pico_add_extra_outputs(solve)