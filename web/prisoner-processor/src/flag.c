#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    setuid(6969);
    FILE *fp = fopen("/home/ghostccamm/flag.txt", "r");
    char buffer[255];
    if (fp == NULL) {
        exit(1);
    }
    fgets(buffer, 255, fp);
    printf("%s\n", buffer);
    fclose(fp);
}