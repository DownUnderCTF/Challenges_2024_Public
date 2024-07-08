#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/gpio.h"
#include "hardware/clocks.h"
#include "hardware/rosc.h"
#include "hardware/pll.h"
#include "mfrc522.h"
#include "bbspi.h"
#include "hardware/structs/rosc.h"

#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"

#define PUBLISH

#ifdef PUBLISH
const uint8_t GLOBAL_SECRET[] = "its ment to be a secret!";
const uint8_t FLAG[] = "DUCTF{fake flag}";
#else
const uint8_t GLOBAL_SECRET[] = "this secret is secret!";
const uint8_t FLAG[] = "DUCTF{D3SF1r3_i5_5ecur3_1f_u53d_corr3ct1y}";
#endif
const uint32_t DF_APP_ID = 0x123456;

// Challenge Management
size_t bbspi_handle_new_cmd(const uint8_t cmd, uint8_t *tx_data)
{
    uint8_t challenge_info[] = {
        0x43, 0x46, 0x43, 0x31,  // CFC1
        0x00, 0x00, 0x00, 0x00,  // no serial
        0x00, 0x00, 0x00, 0x04,  // chal id
        0x49, 0x7f, 0xdc, 0xe8}; // crc32
    if (cmd == 0x03)
    {
        // wait for addr then tx info
        memcpy(tx_data + 3, challenge_info, sizeof(challenge_info));
    }
}

void print_buffer(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        printf("%02x ", buf[i]);
    }
}

uint8_t rand_u8()
{
    uint8_t b = 0;

    for (size_t i = 0; i < 8; i++)
    {
        b |= rosc_hw->randombit;
        b <<= 1;
    }

    return b;
}

void rand_u8p(uint8_t *rnd_out, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        rnd_out[i] = rand_u8();
    }
}

uint32_t rand_u32()
{
    uint32_t r = 0;
    rand_u8p((uint8_t *)&r, sizeof(r));

    return r;
}

void diversify_card_key(Uid *uid, uint8_t key_id, uint8_t *key_out)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);

    mbedtls_sha256_update(&ctx, GLOBAL_SECRET, sizeof(GLOBAL_SECRET));
    mbedtls_sha256_update(&ctx, &key_id, 1);
    mbedtls_sha256_update(&ctx, uid->uidByte, uid->size);

    uint8_t output[32];
    mbedtls_sha256_finish(&ctx, output);

    memcpy(key_out, output, 16); // first 16 bytes make aes-128 key
}

static uint8_t desfire_pcb = 0x0A;
static uint8_t desfire_cid = 0x00;
static uint8_t desfire_session_key[16] = {0};

bool desfire_transcieve(MFRC522Ptr_t mfrc,
                        uint8_t *tx_data, uint8_t tx_size,
                        uint8_t *rx_data, uint8_t *rx_size)
{
    StatusCode ret;

    uint8_t tx_buff[64];
    uint8_t rx_buff[64];

    tx_buff[0] = desfire_pcb;
    tx_buff[1] = desfire_cid;
    memcpy(&tx_buff[2], tx_data, tx_size);

    desfire_pcb = desfire_pcb == 0x0A ? 0x0B : 0x0A; // flip-flop!

    // add CRC
    if ((ret = PCD_CalculateCRC(mfrc, tx_buff, tx_size + 2, &tx_buff[tx_size + 2])) != STATUS_OK)
    {
        printf("transcieve failed - CRC returned non-OK status code: %02x\n\r", ret);
        return false;
    }

    *rx_size += 4;

    // do tx/tx

    if ((ret = PCD_TransceiveData(mfrc, tx_buff, tx_size + 4, rx_buff, rx_size, NULL, 0, true)) != STATUS_OK)
    {
        printf("transcieve failed - MFRC522 returned non-OK status code: %02x\n\r", ret);
        return false;
    }

    *rx_size -= 4;
    memcpy(rx_data, &rx_buff[2], *rx_size);

    return true;
}

bool desfire_pps(MFRC522Ptr_t mfrc, uint8_t cid, uint8_t pps0, uint8_t pps1)
{
    desfire_pcb = 0x0A;

    StatusCode ret;
    uint8_t tx_buffer[5];
    uint8_t rx_buffer[5];
    uint8_t rx_len = 0;

    tx_buffer[0] = 0xD0 | (cid & 0x0F);
    tx_buffer[1] = pps0;
    tx_buffer[2] = pps1;

    // add CRC
    if ((ret = PCD_CalculateCRC(mfrc, tx_buffer, 3, &tx_buffer[3])) != STATUS_OK)
    {
        printf("pps failed - CRC returned non-OK status code: %02x\n\r", ret);
    }

    rx_len = 5;

    if ((ret = PCD_TransceiveData(mfrc, tx_buffer, 5, rx_buffer, &rx_len, NULL, 0, true)) != STATUS_OK)
    {
        printf("pps failed - MFRC522 returned non-OK status code: %02x\n\r", ret);
        return false;
    }

    if (pps1 == 0x00)
    {
        PCD_WriteRegister(mfrc, TxModeReg, 0x00);
        PCD_WriteRegister(mfrc, RxModeReg, 0x00);
    }

    return true;
}

bool desfire_request_ats(MFRC522Ptr_t mfrc)
{
    StatusCode ret;
    uint8_t tx_buffer[4];
    uint8_t rx_buffer[16];
    uint8_t rx_len = 0;
    uint8_t valid_bits = 0;

    tx_buffer[0] = 0xE0; // PICC_CMD_RATS
    tx_buffer[1] = 0x50; // FSD=64, CID=0

    // add CRC
    if ((ret = PCD_CalculateCRC(mfrc, tx_buffer, 2, &tx_buffer[2])) != STATUS_OK)
    {
        printf("request ATS failed - CRC returned non-OK status code: %02x\n\r", ret);
        return false;
    }

    rx_len = 16;

    if ((ret = PCD_TransceiveData(mfrc, tx_buffer, 4, rx_buffer, &rx_len, NULL, 0, true)) != STATUS_OK)
    {
        printf("request ATS failed - MFRC522 returned non-OK status code: %02x\n\r", ret);
        return false;
    }

    return true;
}

bool desfire_select_app(MFRC522Ptr_t mfrc, uint32_t app_id)
{
    StatusCode ret;
    uint8_t tx_buffer[4];
    uint8_t rx_buffer[1];
    uint8_t rx_len = 0;
    uint8_t valid_bits = 0;

    tx_buffer[0] = 0x5A; // select application
    tx_buffer[1] = (uint8_t)((app_id >> 0) & 0xFF);
    tx_buffer[2] = (uint8_t)((app_id >> 8) & 0xFF);
    tx_buffer[3] = (uint8_t)((app_id >> 16) & 0xFF);

    rx_len = 3;

    if (!desfire_transcieve(mfrc, tx_buffer, 4, rx_buffer, &rx_len))
        return false;

    return rx_buffer[0] == 0; // sucess
}

bool desfire_auth_aes(MFRC522Ptr_t mfrc, uint8_t key_id, const uint8_t *key)
{
    mbedtls_aes_context aes;
    uint8_t iv[16] = {0};
    uint8_t tx_buffer[33];
    uint8_t rx_buffer[17];
    uint8_t rx_len = 0;

    uint8_t rand_a[16];
    uint8_t rand_ap[16];
    uint8_t rand_b[16];

    uint8_t enc_buffer[32];

    tx_buffer[0] = 0xAA; // authenticate AES
    tx_buffer[1] = key_id;
    rx_len = 17;

    if (!desfire_transcieve(mfrc, tx_buffer, 2, rx_buffer, &rx_len))
        return false;

    if (rx_buffer[0] != 0xAF)
    {
        printf("card returned error: %02X", rx_buffer[0]);
        return false;
    }

    if (mbedtls_aes_setkey_dec(&aes, key, 128) != 0)
    {
        printf("failed to set dec key");
        return false;
    }

    if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, &rx_buffer[1], rand_b) != 0)
    {
        printf("failed to decrypt");
        return false;
    }

    rand_u8p(rand_a, sizeof(rand_a));
    memcpy(enc_buffer, rand_a, 16);
    // rand b'
    memcpy(&enc_buffer[16], &rand_b[1], sizeof(rand_b));
    enc_buffer[31] = rand_b[0];

    // rand a'
    memcpy(rand_ap, &rand_a[1], sizeof(rand_ap) - 1);
    rand_ap[15] = rand_a[0];

    // iv
    memcpy(iv, &rx_buffer[1], sizeof(iv));

    // encrypt
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0)
    {
        printf("failed to set enc key");
        return false;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv, enc_buffer, &tx_buffer[1]))
    {
        printf("failed to encrypt");
        return false;
    }

    tx_buffer[0] = 0xAF; // additional frame
    rx_len = 17;
    if (!desfire_transcieve(mfrc, tx_buffer, 33, rx_buffer, &rx_len))
        return false;

    if (rx_len != 17 || rx_buffer[0] != 0)
    {
        printf("card returned error: %02X", rx_buffer[0]);
        return false;
    }

    if (mbedtls_aes_setkey_dec(&aes, key, 128) != 0)
    {
        printf("failed to set dec key");
        return false;
    }

    memcpy(iv, &tx_buffer[17], sizeof(iv));

    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, &rx_buffer[1], &rx_buffer[1]) != 0)
    {
        printf("failed to decrypt");
        return false;
    }

    // printf("K: ");
    // print_buffer(key, 16);
    // printf("\nA: ");
    // print_buffer(rand_a, 16);
    // printf("\nA': ");
    // print_buffer(rand_ap, 16);
    // printf("\nIV: ");
    // print_buffer(iv, 16);
    // printf("\nPayload: ");
    // print_buffer(&rx_buffer[1], 16);
    // printf("\n");

    if (memcmp(&rx_buffer[1], rand_ap, sizeof(rand_ap)) != 0)
    {
        printf("a' mismatch");
        return false;
    }

    // auth good! session key time!
    memcpy(&desfire_session_key[0], &rand_a[0], 4);
    memcpy(&desfire_session_key[4], &rand_b[0], 4);
    memcpy(&desfire_session_key[8], &rand_a[12], 4);
    memcpy(&desfire_session_key[12], &rand_b[12], 4);

    return true;
}

bool desfire_write_data(MFRC522Ptr_t mfrc, const uint8_t file_id, const uint32_t offset, const uint32_t data_length, const uint8_t *data)
{
    uint8_t tx_buffer[33];
    uint8_t rx_buffer[64];
    uint8_t rx_len = 0;

    tx_buffer[0] = 0x3D;
    tx_buffer[1] = file_id;

    tx_buffer[2] = (uint8_t)((offset >> 0) & 0xFF);
    tx_buffer[3] = (uint8_t)((offset >> 8) & 0xFF);
    tx_buffer[4] = (uint8_t)((offset >> 16) & 0xFF);

    tx_buffer[5] = (uint8_t)((data_length >> 0) & 0xFF);
    tx_buffer[6] = (uint8_t)((data_length >> 8) & 0xFF);
    tx_buffer[7] = (uint8_t)((data_length >> 16) & 0xFF);

    rx_len = 64;

    memcpy(&tx_buffer[8], data, data_length);

    if (!desfire_transcieve(mfrc, tx_buffer, 8 + data_length, rx_buffer, &rx_len))
        return false;

    return rx_buffer[0] == 0;
}

int main()
{
    rosc_set_div(1);
    rosc_set_freq(0x00001111);
    stdio_init_all();

#ifndef PUBLISH
    bbspi_init(9, 10, 8, 11);
#endif

    gpio_set_inover(17, GPIO_OVERRIDE_NORMAL);
    gpio_set_inover(18, GPIO_OVERRIDE_NORMAL);
    gpio_set_inover(19, GPIO_OVERRIDE_NORMAL);
    gpio_set_inover(20, GPIO_OVERRIDE_NORMAL);

    gpio_set_outover(17, GPIO_OVERRIDE_NORMAL);
    gpio_set_outover(18, GPIO_OVERRIDE_NORMAL);
    gpio_set_outover(19, GPIO_OVERRIDE_NORMAL);
    gpio_set_outover(20, GPIO_OVERRIDE_NORMAL);

    MFRC522Ptr_t mfrc = MFRC522_Init();

    while (true)
    {
        PCD_Init(mfrc, spi0);

        PCD_DumpVersionToSerial(mfrc);

        uint8_t version_b = PCD_ReadRegister(mfrc, VersionReg);

        if (version_b == 0x00 || version_b == 0xFF)
        {
            // comms failed :(
            printf("Failed to communicate with MFRC522 - retrying\n");
        }
        else
        {
            printf("MFRC522 Initialized Successfully\n");
            break;
        }
    }

    sleep_ms(5000);

    while (true)
    {
        printf("Waiting for card\n\r");
        while (!PICC_IsNewCardPresent(mfrc))
        {
            ;
        }

        printf("Selecting card\n\r");
        PICC_ReadCardSerial(mfrc);

        uint8_t card_key[16] = {0};
        diversify_card_key(&mfrc->uid, 1, card_key);

        if (!desfire_request_ats(mfrc) || !desfire_pps(mfrc, 0x00, 0x11, 0x00))
        {
            printf("Failed to setup card communications\n\r");
            PICC_HaltA(mfrc);
            continue;
        }

        if (!desfire_select_app(mfrc, DF_APP_ID))
        {
            printf("Failed to select application\n\r");
            PICC_HaltA(mfrc);
            continue;
        }

        if (!desfire_auth_aes(mfrc, 1, card_key))
        {
            printf("Failed to authenticate application\n\r");
            PICC_HaltA(mfrc);
            continue;
        }

        if (!desfire_write_data(mfrc, 0x01, 0x0, sizeof(FLAG), FLAG))
        {
            printf("Failed to write data\n\r");
            PICC_HaltA(mfrc);
            continue;
        }

        printf("Balance updated successfully");
    }
}
