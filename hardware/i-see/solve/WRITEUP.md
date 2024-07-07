# I See

There is an I2C M24C01 EEPROM attached on IO24 and IO25.
The challenge simply calls for reading the EEPROM, and sending it back to the attacker using the UART passthrough of the infrastructure.
An example solve script is provided in [main.rs](./main.rs).
Compile this to an ELF with `cargo build`, and submit the binary for execution.

Other solutions could include using micropython, or the pico-sdk to read the EEPROM.
