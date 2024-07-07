#include <stdio.h>
#include <errno.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>

const volatile uint8_t *flag_ptr = (uint8_t *)0xDEAD0000;
const volatile uint8_t *sbox_ptr = (uint8_t *)0xBEEF0000;

/*
[mod(39*b, 256) for b in b"DUCTF{m3m3_m4p_or_m3mmap_d45832a29d}"]
*/

const uint8_t flag[] = {99, 250, 60, 211, 177, 196, 162, 204, 162, 204, 128, 162, 243, 23, 128, 240, 101, 128, 162, 204, 162, 162, 206, 23, 128, 67, 243, 26, 143, 204, 165, 206, 165, 182, 67, 18};
const size_t flag_len = sizeof(flag);

const uint8_t banner[] = ("                    _       _                 _ _             \n"
                          "  ___ _ __ __ _ ___| |__   | | __ _ _ __   __| (_)_ __   __ _ \n"
                          " / __| '__/ _` / __| '_ \\  | |/ _` | '_ \\ / _` | | '_ \\ / _` |\n"
                          "| (__| | | (_| \\__ \\ | | | | | (_| | | | | (_| | | | | | (_| |\n"
                          " \\___|_|  \\__,_|___/_| |_| |_|\\__,_|_| |_|\\__,_|_|_| |_|\\__, |\n"
                          "                                                        |___/ \n"
                          "\n"
                          "Our kiwi friend needs some help unlocking his wings.\n"
                          "Looks like we need an unlock code. Any ideas?\n");

typedef struct __attribute__((packed)) ContextStateFrame
{
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r12;
    uint32_t lr;
    uint32_t return_address;
    uint32_t xpsr;
} sContextStateFrame;

void hard_fault_handler(void)
{
    __asm__ volatile(
        "tst lr, #4 \n"
        "ite eq \n"
        "mrseq r0, msp \n"
        "mrsne r0, psp \n"
        "b hard_fault_handler_c \n");
}

__attribute__((optimize("O0"))) void hard_fault_handler_c(sContextStateFrame *frame)
{
    uint32_t cfsr = *((uint32_t *)0xE000ED28);
    uint32_t bfar = *((uint32_t *)0xE000ED38);

    if (cfsr & 0x8200) // precise and bfar valid
    {
        if ((bfar & 0xFFFF0000) == (uint32_t)flag_ptr)
        {
            frame->r3 = flag[bfar & 0xFFFF];
            frame->return_address += 2;
            return;
        }
        else if ((bfar & 0xFFFF0000) == (uint32_t)sbox_ptr)
        {
            frame->r3 = (39 * (bfar & 0xFF) + 7) % 256; // affine cipher
            frame->return_address += 2;
            return;
        }
    }

    while (1)
    {
        ;
    }
}

uint32_t read_memmaped_u32(uint32_t *addr)
{
    uint32_t ret = 0;
    __asm__ volatile(
        "ldr r3, [%1] \n\t"
        "mov %0, r3"
        : "=r"(ret)
        : "r"(addr));

    return ret;
}

uint8_t read_memmaped_u8(uint8_t *addr)
{
    return (uint8_t)read_memmaped_u32(addr);
}

// stdio printf
int _write(int file, char *ptr, int len);
int _write(int file, char *ptr, int len)
{
    int i;

    if (file == 1)
    {
        for (i = 0; i < len; i++)
            usart_send_blocking(USART1, ptr[i]);
        return i;
    }

    errno = EIO;
    return -1;
}

static void usart_setup(void)
{
    usart_set_baudrate(USART1, 115200);
    usart_set_databits(USART1, 8);
    usart_set_stopbits(USART1, USART_STOPBITS_1);
    usart_set_parity(USART1, USART_PARITY_NONE);
    usart_set_flow_control(USART1, USART_FLOWCONTROL_NONE);
    usart_set_mode(USART1, USART_MODE_TX_RX);
    usart_enable(USART1);
}

int main(void)
{
    uint8_t unlock_code_buf[128];

    usart_setup();

    setvbuf(stdout, NULL, _IONBF, 0);

    while (1)
    {
        printf("%s\n", banner);
        printf("Unlock Code > ");

        size_t i = 0;
        while (i < sizeof(unlock_code_buf))
        {
            uint8_t ch = usart_recv_blocking(USART1);
            usart_send_blocking(USART1, ch);

            if (ch == 0x0d || ch == '\n')
            {
                unlock_code_buf[i] = 0;
                break;
            }
            unlock_code_buf[i++] = ch;
        }

        printf("\nI'll give that a try!\n");

        bool is_valid = i == flag_len;
        for (size_t j = 0; j < i; j++)
        {
            uint8_t secret_char = read_memmaped_u8(&flag_ptr[j]);
            uint8_t sbox_mapping = read_memmaped_u8(&sbox_ptr[unlock_code_buf[j]]);

            if (secret_char != sbox_mapping)
            {
                is_valid = false;
            }
        }

        if (is_valid)
        {
            printf("DLC unlocked! You can now fly!\n");
            break;
        }
        else
        {
            printf("Hmm nope, that unlock code didn't work. Try again!\n");
        }
    }

    return 0;
}