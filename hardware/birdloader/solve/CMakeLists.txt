cmake_minimum_required(VERSION 3.13)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
set(PICO_SDK_FETCH_FROM_GIT on)
include(pico_sdk_import.cmake)

project(my_project)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# rest of your project


add_executable(solver
        solver.c
        )



# Add pico_stdlib library which aggregates commonly used features
target_link_libraries(solver pico_stdlib)

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(solver)

# enable uart output, disable usb output
pico_enable_stdio_usb(solver 0)
pico_enable_stdio_uart(solver 1)

