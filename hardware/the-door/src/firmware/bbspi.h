#include <stddef.h>
#include <stdint.h>

void bbspi_init(uint32_t cs, uint32_t sck, uint32_t mosi, uint32_t miso);

size_t bbspi_handle_new_cmd(const uint8_t cmd, uint8_t *tx_data);

void bbspi_gpio_callback_passthrough(uint16_t gpio, uint16_t events);