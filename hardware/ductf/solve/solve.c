#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bbspi.h"
#include "pico/stdlib.h"
#include "hardware/spi.h"

uint8_t rand_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

enum
{
    PCD_Idle = 0x00,
    PCD_CalcCRC = 0x03,
    PCD_Transceive = 0x0C,
    PCD_SoftReset = 0x0F
} last_command;

enum
{
    CommandReg = 0x01,
    ComIrqReg = 0x04,
    DivIrqReg = 0x05,
    ErrorReg = 0x06,
    FIFODataReg = 0x09,
    FIFOLevelReg = 0x0A,
    ControlReg = 0x0C,
    VersionReg = 0x37,
};

enum
{
    PICC_CMD_REQA = 0x26
};

uint8_t fifo_tx_len = 0;
uint8_t fifo_tx_buf[128] = {0};
uint8_t fifo_rx_i = 0;
uint8_t fifo_rx_len = 0;
uint8_t fifo_rx_buf[128] = {0};

size_t handle_apdu(const uint8_t *rx_apdu, const size_t rx_apdu_len, uint8_t *tx_apdu)
{
    static uint8_t stage = 0;
    static uint8_t rand_a_enc[16] = {0};
    static uint8_t final_iv[16] = {0};
    static uint8_t final_step_enc[16] = {0};

    if (stage == 4)
    {
        puts("Exiting");
        fflush(stdout);
        exit(0);
    }

    printf(" --> Attack stage %hi\n", stage);

    if (rx_apdu[0] == 0x5A)
    {
        // Select Application
        tx_apdu[0] = 0x00; // OK
        return 1;
    }
    else if (rx_apdu[0] == 0xAA)
    {
        // Authenticate AES
        tx_apdu[0] = 0xAF; // additional frame

        if (stage == 0)
        {
            // Will encrypt rand_a for us
            memset(tx_apdu + 1, 0, 16); // all 0s.
        }
        else if (stage == 1)
        {
            memcpy(tx_apdu + 1, rand_a_enc, 16); // encrypted rand_a
        }
        else if (stage == 2)
        {
            // Encrypt rand_a ^ final_iv
            memcpy(tx_apdu + 1, final_iv, 16);
        }
        else if (stage == 3)
        {
            memcpy(tx_apdu + 1, rand_a_enc, 16); // encrypted rand_a
        }

        return 17;
    }
    else if (rx_apdu[0] == 0xAF)
    {
        // AES part 2

        // First 16 bytes contain enc(stage 0 ciphertext ^ rand_a)

        if (stage == 0)
        {
            memcpy(rand_a_enc, rx_apdu + 1, 16);

            printf("rnd_a_enc: ");
            for (size_t i = 0; i < 16; i++)
            {
                printf("%02x ", rand_a_enc[i]);
            }
            printf("\n");

            stage++;

            return 1; // we cant auth this any further - abandon it!
        }
        else if (stage == 1)
        {

            // the IV for the final encryption (last half of message)
            memcpy(final_iv, rx_apdu + 1 + 16, 16);

            printf("final_iv: ");
            for (size_t i = 0; i < 16; i++)
            {
                printf("%02x ", final_iv[i]);
            }
            printf("\n");

            stage++;

            return 1;
        }
        else if (stage == 2)
        {
            // This is our final step return value:
            memcpy(final_step_enc, rx_apdu + 1, 16);
            stage++;

            printf("final_step_enc: ");
            for (size_t i = 0; i < 16; i++)
            {
                printf("%02x ", final_step_enc[i]);
            }
            printf("\n");

            return 1;
        }
        else if (stage == 3)
        {
            tx_apdu[0] = 0x00;                       // OK
            memcpy(tx_apdu + 1, final_step_enc, 16); // all 0s.

            return 17;
        }
    }
    else if (rx_apdu[0] == 0x3D)
    {
        // FLAG!
        printf("Flag: %s\n", rx_apdu + 1 + 1 + 3 + 3);
        stage++;
    }
}

// handle a data transcieve
void handle_command(uint8_t cmd)
{
    if (cmd == PCD_Transceive)
    {
        if (fifo_tx_buf[0] == PICC_CMD_REQA)
        {
            printf(" -> REQA\n");
            // REQA, lets respond with 2 bytes - these don't get checked.
            fifo_rx_buf[0] = 0xAA;
            fifo_rx_buf[1] = 0xAA;

            fifo_rx_len = 2;
        }
        else if (fifo_tx_buf[0] == 0xE0)
        {
            printf(" -> RATS\n");
            fifo_rx_buf[0] = 0xAA;
            // CRC16
            fifo_rx_buf[1] = 0x00;
            fifo_rx_buf[2] = 0x00;

            fifo_rx_len = 3;
        }
        else if (fifo_tx_buf[0] == 0xD0)
        {
            printf(" -> PPS\n");
            fifo_rx_buf[0] = 0xAA;

            // CRC16
            fifo_rx_buf[1] = 0x00;
            fifo_rx_buf[2] = 0x00;

            fifo_rx_len = 3;
        }
        else if (fifo_tx_buf[0] == 0x0A || fifo_tx_buf[0] == 0x0B)
        {
            printf(" -> APDU\nRX: ");

            for (size_t i = 0; i < fifo_tx_len; i++)
            {
                printf("%02x ", fifo_tx_buf[i]);
            }
            printf("\n");

            fifo_rx_buf[0] = fifo_tx_buf[0];
            fifo_rx_buf[1] = fifo_tx_buf[1];

            size_t apdu_len = handle_apdu(fifo_tx_buf + 2, fifo_tx_len - 4, fifo_rx_buf + 2);

            fifo_rx_buf[apdu_len + 2] = 0x00;
            fifo_rx_buf[apdu_len + 3] = 0x00;
            fifo_rx_len = apdu_len + 4;

            printf("TX: ");
            for (size_t i = 0; i < fifo_rx_len; i++)
            {
                printf("%02x ", fifo_rx_buf[i]);
            }
            printf("\n");
        }
    }
}

void __time_critical_func(register_write_callback)(uint8_t reg, uint8_t val)
{
    // printf("Register %02X written as %02X\n", reg, val);

    if (reg == CommandReg)
    {
        if (last_command == PCD_Idle && val != PCD_SoftReset)
        {
            handle_command(val);
        }
        last_command = val;
    }

    else if (reg == FIFOLevelReg)
    {
        if (val & 0x80) // Flush buffers
        {
            fifo_tx_len = 0;
            fifo_rx_len = 0;
            fifo_rx_i = 0;
        }
    }
    else if (reg == FIFODataReg)
    {
        fifo_tx_buf[fifo_tx_len++] = val;
    }
}

uint8_t __time_critical_func(register_read_callback)(uint8_t reg)
{

    if (reg == VersionReg)
    {
        return 0x92;
    }
    else if (reg == ComIrqReg)
    {
        return 0x30; // all the interrupts! - breaks PCD_CommunicateWithPICC ASAP
    }
    else if (reg == DivIrqReg)
    {
        return 0x04; // our CRCs are always done! - they are always 0x0000
    }
    else if (reg == ErrorReg)
    {
        return 0; // we are perfect and never have any errors!
    }
    else if (reg == FIFOLevelReg)
    {
        return fifo_rx_len;
    }
    else if (reg == FIFODataReg)
    {
        if (fifo_rx_len == fifo_rx_i)
            return 0;
        return fifo_rx_buf[fifo_rx_i++];
    }
    else if (reg == ControlReg)
    {
        return 0; // we only tx in 8-bit bytes
    }
    return 0;
}

size_t bbspi_handle_rx(const uint8_t *rx_data, const size_t rx_count, uint8_t *tx_data)
{
    if (rx_count > 0)
    {
        uint8_t reg = rx_data[0];
        if (reg & 0x80)
        {
            // read request
            uint8_t ret = register_read_callback((reg & 0x7F) >> 1);
            tx_data[1] = ret; // write back after this

            // printf("read: %02X (%02X) = %02X\n", reg, (reg & 0x7F) >> 1, ret);
        }
        else if (rx_count == 2) // 2 bytes
        {
            // write request
            uint8_t val = rx_data[1];

            register_write_callback((reg & 0x7F) >> 1, val);

            // printf("write: %02X (%02X) = %02X\n", reg, (reg & 0x7F) >> 1, val);
        }
    }
}

int main()
{
    stdio_init_all();

    sleep_ms(3000);

    puts("DUCTF Solve Script");

    bbspi_init(17, 18, 20, 19);

    while (true)
    {
    }
}