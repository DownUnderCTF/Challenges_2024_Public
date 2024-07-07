#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/random.h>
#include <mbedtls/poly1305.h>

#define TARGET_MESSAGE "I have broken Poly1305 one time MAC!"

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu() {
    puts("1. Get one-time MAC");
    puts("2. Verify one-time MAC");
    printf("> ");
}

void randomize_key(char* key) {
    if(getrandom(key, 16, 0) != 16) {
        printf("Failed to randomize key\n");
        exit(1);
    }
}

int bytes_fromhex(char* in, char* out) {
    size_t in_len = strlen(in);
    if(in_len % 2 != 0) return -1;

    for(int i = 0; i < in_len; i+=2) {
        char c1 = in[i];
        char c2 = in[i+1];
        if(!isxdigit(c1) || !isxdigit(c2)) {
            return -1;
        }
        char v = 0;
        v |= (c1 - (isdigit(c1) ? '0' : (islower(c1) ? 'W' : '7'))) << 4;
        v |= (c2 - (isdigit(c2) ? '0' : (islower(c2) ? 'W' : '7')));
        out[i / 2] = v;
    }

    return in_len / 2;
}

void get_otm(char* key) {
    char mac[16] = { 0 };
    char msg[65] = { 0 };

    randomize_key(key);

    printf("message: ");
    scanf("%64s", msg);
    int len = bytes_fromhex(msg, msg);
    if(len <= 0) {
        exit(1);
    }

    mbedtls_poly1305_mac(key, msg, len, mac);

    for(int i = 0; i < 16; i++) {
        printf("%02x", (unsigned char)mac[i]);
    }
    printf("\n");
}

void verify_otm(char* key) {
    char mac[16] = {0};
    char provided_mac[33] = {0};

    printf("mac: ");
    scanf("%32s", provided_mac);
    int len = bytes_fromhex(provided_mac, provided_mac);
    if(len != 16) {
        exit(1);
    }

    mbedtls_poly1305_mac(key, TARGET_MESSAGE, strlen(TARGET_MESSAGE), mac);

    if(memcmp(mac, provided_mac, 16) == 0) {
        system("cat flag.txt");
    } else {
        printf("Not the right MAC...\n");
    }
}

int main() {
    void (*option_funcs[2])(char*) = { get_otm, verify_otm };
    char key[16] = { 0 };
    int choice, i, remaining;
    remaining = 35;

    init();
    randomize_key(key);

    while(remaining--) {
        menu();
        scanf("%d", &choice);
        if(choice != 1 && choice != 2) exit(1);
        option_funcs[choice - 1](key);
    }

    printf("Good bye\n");
}
