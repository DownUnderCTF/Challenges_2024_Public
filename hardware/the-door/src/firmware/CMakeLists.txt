cmake_minimum_required(VERSION 3.13)

set(PICO_SDK_FETCH_FROM_GIT on)

include(pico_sdk_import.cmake) # modified to apply picopatch.sdk

project(the_door)

pico_sdk_init()

add_executable(the_door main.c bbspi.c)
pico_enable_stdio_uart(the_door 1)
pico_enable_stdio_usb(the_door 0)



target_link_libraries(the_door pico_rand pico_stdlib hardware_spi hardware_irq hardware_gpio)
target_include_directories(the_door PRIVATE ${CMAKE_CURRENT_LIST_DIR})



# create map/bin/hex file etc.
pico_add_extra_outputs(the_door)