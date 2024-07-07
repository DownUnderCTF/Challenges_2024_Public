#include <stdio.h>
#include <stdlib.h>

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);

    int x, y;
    printf("Give me some numbers: ");
    scanf("%d %d", &x, &y);
    if(x == 0 || y == 0 || y == 1) {
        puts("Nope!");
        exit(1);
    }
    int z = x / y;
    if(z != x) {
        puts("Nope!");
        exit(1);
    }
    char flag[0x100] = {0};
    FILE* f = fopen("flag.txt", "r");
    fread(flag, 1, 0x100, f);
    printf("Correct! %s\n", flag);
}
