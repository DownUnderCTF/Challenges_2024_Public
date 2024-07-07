#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[8];
    void (*fptr)();
} builtin_func;

void ls() {
    system("ls");
}

void read64() {
    unsigned long* addr;
    printf("read64> ");
    scanf("%p", &addr);
    printf("%8lx\n", *addr);
}

void write64() {
    unsigned long* addr;
    unsigned long val;
    printf("write64> ");
    scanf("%p %lx", &addr, &val);
    *addr = val;
}

void help();
builtin_func BUILTINS[4] = {
    { .name = "help", .fptr = help },
    { .name = "ls", .fptr = ls },
    { .name = "read64", .fptr = read64 },
    { .name = "write64", .fptr = write64 },
};

void help() {
    void (*f)();
    for(int i = 0; i < 4; i++) {
        f = BUILTINS[i].fptr;
        __asm__("paciza %0\n" : "=r"(f) : "r"(f));
        printf("%8s: %p\n", BUILTINS[i].name, f);
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    void (*fptr)() = NULL;

    puts("Welcome to pac shell v0.0.1");
    help();

    while(1) {
        printf("pacsh> ");
        scanf("%p", &fptr);
        __asm__("autiza %0\n" : "=r"(fptr) : "r"(fptr));
        (*fptr)();
    }
}
