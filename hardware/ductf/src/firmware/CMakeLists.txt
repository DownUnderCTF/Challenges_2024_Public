cmake_minimum_required(VERSION 3.13)

set(PICO_SDK_FETCH_FROM_GIT on)
set(PICO_EXTRAS_FETCH_FROM_GIT on)

include(pico_sdk_import.cmake) # modified to apply picopatch.sdk
include(pico_extras_import.cmake)

project(ductf)

pico_sdk_init()



# Heavily based on https://github.com/BenjaminModica/pico-mfrc522/tree/main
add_library(pico_mfrc522 mfrc522.c)
target_include_directories(pico_mfrc522 INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(pico_mfrc522 pico_stdlib hardware_spi)

add_executable(ductf ductf.c bbspi.c)
pico_enable_stdio_uart(ductf 1)
pico_enable_stdio_usb(ductf 0)



target_link_libraries(ductf pico_stdlib pico_mbedtls pico_mfrc522 hardware_spi hardware_clocks hardware_rosc hardware_irq hardware_gpio)
target_include_directories(ductf PRIVATE ${CMAKE_CURRENT_LIST_DIR})



# create map/bin/hex file etc.
pico_add_extra_outputs(ductf)