#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned char KEY[32] = {39, 183, 80, 100, 154, 6, 152, 255, 205, 48, 133, 244, 190, 87, 176, 17, 218, 128, 190, 112, 22, 61, 74, 79, 249, 251, 136, 63, 45, 181, 162, 241};
const unsigned char Z[32] = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";

int main() {
    char cmd[0x1000];
    char hexKey[65] = {0};
    char* tmp;

    tmp = hexKey;
    for(int i = 0; i < 32; i++) {
        tmp += sprintf(tmp, "%02x", KEY[i]);
    }
    sprintf(cmd, "/usr/bin/aea encrypt -i cat.png -key-value hex:%s -o cat.png.aea", hexKey);
    system(cmd);

    FILE* f = fopen("cat.png.aea", "r");
    fseek(f, 0, SEEK_END);
    size_t fs = ftell(f);
    fseek(f, 0, SEEK_SET);
    tmp = malloc(fs);
    fread(tmp, 1, fs, f);
    fclose(f);

    unsigned char k1[32] = {0};
    unsigned char k2[32] = {0};

    memcpy(k1, &tmp[0xa4], 0x20);
    memcpy(k2, &tmp[0x28bc], 0x20);

    f = fopen("cat.png.aea", "w");
    memcpy(&tmp[0xa4], Z, 0x20);
    memcpy(&tmp[0x28bc], Z, 0x20);
    fwrite(tmp, 1, fs, f);
    fclose(f);

    tmp = hexKey;
    for(int i = 0; i < 32; i++) {
        tmp += sprintf(tmp, "%02x", k1[i] ^ k2[i]);
    }
    memset(cmd, 0, 0x1000);
    sprintf(cmd, "/usr/bin/aea encrypt -i flag.txt -key-value hex:%s -o flag.txt.aea", hexKey);
    system(cmd);

}
