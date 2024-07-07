#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include "pico/stdlib.h"

#define PIN_WDAT 5
#define PIN_RCLK 4
#define PIN_WCLK 3

#define n 32
#define TOTAL_DATA ((uint64_t)((1 << n) - 1))

#define SET_BIT(word, num, new) ((word) & ~(1LL << (num)) | ((new) << (num)))
#define GET_BIT(word, num) (((word) >> (num)) & 1)

volatile uint32_t seq_buffer = 0;
uint8_t seq_buffer_valid = 0;

uint32_t total_data_sent = 0;

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

void shift_u32(uint32_t c)
{
    for (size_t i = 0; i < 32; i++)
    {
        shift_bit(c & 1);
        c >>= 1;
    }
}

// k = 2
void __time_critical_func(fmk_gen_debrujin)(uint8_t t, uint8_t p, uint64_t *a)
{
    if (t > n)
    {
        if (n % p == 0)
        {
            uint8_t valid_bits = p;
            uint32_t data = *a >> 1;

            for (int i = 0; i < valid_bits; i++)
            {
                bool bit = data & 1;
                data >>= 1;

                seq_buffer >>= 1;
                seq_buffer |= bit ? 1 : 0;
                seq_buffer_valid++;

                shift_bit(bit);

                if (seq_buffer_valid == 32)
                {

                    total_data_sent += seq_buffer_valid;
                    seq_buffer_valid = 0;

                    if (total_data_sent % 0x1000000 == 0)
                    {
                        printf("%u / %u (%.2f %%) \n", total_data_sent, TOTAL_DATA, ((float)(total_data_sent)) / ((float)(TOTAL_DATA)) * 100);
                    }
                }
            }
        }
    }
    else
    {
        *a = SET_BIT(*a, t, GET_BIT(*a, t - p));
        fmk_gen_debrujin(t + 1, p, a);
        if (GET_BIT(*a, t - p) == 0)
        {
            *a = SET_BIT(*a, t, 1);
            fmk_gen_debrujin(t + 1, t, a);
        }
    }
}

int main()
{
    stdio_init_all();
    sleep_ms(3000);
    puts("The Door Solve Script");

    gpio_init(PIN_WDAT);
    gpio_init(PIN_RCLK);
    gpio_init(PIN_WCLK);
    gpio_set_dir(PIN_WDAT, GPIO_OUT);
    gpio_set_dir(PIN_RCLK, GPIO_OUT);
    gpio_set_dir(PIN_WCLK, GPIO_OUT);

    // uint offset = pio_add_program(pio0, &solve_program);

    // solve_program_init(pio0, 0, offset, 5, 3);

    uint64_t a = 0;
    fmk_gen_debrujin(1, 1, &a);

    sleep_ms(1000);

    puts("attempted all possible values");
    exit(0);
    while (1)
    {
    }
}