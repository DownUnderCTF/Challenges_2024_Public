#include <stdbool.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "bbspi.h"

#define PIN_WDAT 10
#define PIN_RCLK 11
#define PIN_WCLK 12

#define PIN_FLAG_RELEASE 13

static bool release_flag = false;

size_t bbspi_handle_new_cmd(const uint8_t cmd, uint8_t *tx_data)
{
    uint8_t challenge_info[] = {
        0x43, 0x46, 0x43, 0x31,  // CFC1
        0x00, 0x00, 0x00, 0x00,  // no serial
        0x00, 0x00, 0x00, 0x02,  // chal id
        0xa0, 0x1c, 0x79, 0xdd}; // crc32
    if (cmd == 0x03)
    {
        // wait for addr then tx info
        memcpy(tx_data + 3, challenge_info, sizeof(challenge_info));
        release_flag = false;
    }
    else if (cmd == 0x0F) // Flag release command
    {
        tx_data[0] = release_flag ? 0x81 : 0x80; // not 0 so we can test RX is working too - last bit represents flag release
    }
}

void shift_bit(bool bit)
{
    gpio_put(PIN_WDAT, bit);

    // 'clock'
    gpio_put(PIN_WCLK, true);
    gpio_put(PIN_RCLK, false);
    sleep_ms(64);
    gpio_put(PIN_WCLK, false);
    gpio_put(PIN_RCLK, true);
    sleep_ms(64);

    gpio_put(PIN_RCLK, false);
}

void shift_u32(uint32_t n)
{
    for (size_t i = 0; i < 32; i++)
    {
        shift_bit(n & 1);
        n >>= 1;
    }
}

void bbspi_gpio_callback_passthrough(uint16_t gpio, uint16_t events)
{
    if (gpio == PIN_FLAG_RELEASE && events & (GPIO_IRQ_EDGE_FALL | GPIO_IRQ_EDGE_RISE))
    {
        // somehow flag release changed - good enough for a release!
        release_flag = true;
    }
}

int main()
{
    stdio_init_all();

    gpio_init(PIN_WDAT);
    gpio_init(PIN_RCLK);
    gpio_init(PIN_WCLK);
    gpio_init(PIN_FLAG_RELEASE);

    gpio_set_dir(PIN_WDAT, GPIO_OUT);
    gpio_set_dir(PIN_RCLK, GPIO_OUT);
    gpio_set_dir(PIN_WCLK, GPIO_OUT);

    gpio_set_dir(PIN_FLAG_RELEASE, GPIO_IN);

    shift_u32(0b00011000000000000000000000000000); // a debrujin will catch this trivially, guessing, not so much

    gpio_set_irq_enabled(PIN_FLAG_RELEASE, GPIO_IRQ_EDGE_FALL | GPIO_IRQ_EDGE_RISE, true);

    bbspi_init(5, 6, 4, 3);

    while (1)
    {
    }
}