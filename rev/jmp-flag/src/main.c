#include <stdio.h>

unsigned long out = 0xffffffffffffffff;

int check() {
    return out == 0;
}

void process(char c) {
    asm(
        "mov %0, %%r11;"
        "lea 0(%%rip), %%rax;"
        "add %%r11, %%rax;"
        "lea 0(%%rip), %%rbx;"
        "add $8, %%rbx;"
        "push %%rbx;"
        "jmp *%%rax;"
        : :"r"((unsigned long)c * 128 + 96)
    );
}

void func00() { out |= -1; }
void func01() { out |= -1; }
void func02() { out |= -1; }
void func03() { out |= -1; }
void func04() { out |= -1; }
void func05() { out |= -1; }
void func06() { out |= -1; }
void func07() { out |= -1; }
void func08() { out |= -1; }
void func09() { out |= -1; }
void func0a() { out |= -1; }
void func0b() { out |= -1; }
void func0c() { out |= -1; }
void func0d() { out |= -1; }
void func0e() { out |= -1; }
void func0f() { out |= -1; }
void func10() { out |= -1; }
void func11() { out |= -1; }
void func12() { out |= -1; }
void func13() { out |= -1; }
void func14() { out |= -1; }
void func15() { out |= -1; }
void func16() { out |= -1; }
void func17() { out |= -1; }
void func18() { out |= -1; }
void func19() { out |= -1; }
void func1a() { out |= -1; }
void func1b() { out |= -1; }
void func1c() { out |= -1; }
void func1d() { out |= -1; }
void func1e() { out |= -1; }
void func1f() { out |= -1; }
void func20() { out |= -1; }
void func21() { !(out & 8646876026610122750) && (out ^= 35184372088832); }
void func22() { out |= -1; }
void func23() { out |= -1; }
void func24() { out |= -1; }
void func25() { out |= -1; }
void func26() { out |= -1; }
void func27() { out |= -1; }
void func28() { out |= -1; }
void func29() { out |= -1; }
void func2a() { out |= -1; }
void func2b() { out |= -1; }
void func2c() { out |= -1; }
void func2d() { out |= -1; }
void func2e() { out |= -1; }
void func2f() { out |= -1; }
void func30() { !(out & 8646876018020179966) && (out ^= 8589934592); }
void func31() { !(out & 281475010396160) && (out ^= 262144); }
void func32() { !(out & 8646726484170366974) && (out ^= 140737488355328); }
void func33() { !(out & 4647996290465431560) && (out ^= 64); }
void func34() { !(out & 17870283320868208639) && (out ^= 536870912); }
void func35() { !(out & 36310272038010888) && (out ^= 4611686018427387904); }
void func36() { !(out & 8646721261490132990) && (out ^= 549755813888); }
void func37() { !(out & 4647996427908579660) && (out ^= 2305843009213693952); }
void func38() { !(out & 8636021879276552670) && (out ^= 512); }
void func39() { !(out & 8636585963171070942) && (out ^= 4096); }
void func3a() { out |= -1; }
void func3b() { out |= -1; }
void func3c() { out |= -1; }
void func3d() { out |= -1; }
void func3e() { out |= -1; }
void func3f() { !(out & 8487403088352100830) && (out ^= 1073741824); }
void func40() { out |= -1; }
void func41() { !(out & 33554432) && (out ^= 131072); }
void func42() { !(out & 8636023013217649630) && (out ^= 562949953421312); }
void func43() { !(out & 8646876017751744510) && (out ^= 268435456); }
void func44() { !(out & 8646911279701688318) && (out ^= 1); }
void func45() { !(out & 4647996427904385100) && (out ^= 4194304); }
void func46() { !(out & 36310272029622272) && (out ^= 8388608); }
void func47() { !(out & 8646911284013432831) && (out ^= 9223372036854775808); }
void func48() { !(out & 281475010658304) && (out ^= 36028797018963968); }
void func49() { !(out & 8636585963171075038) && (out ^= 32); }
void func4a() { !(out & 8199172712200389086) && (out ^= 288230376151711744); }
void func4b() { !(out & 36310272038010880) && (out ^= 8); }
void func4c() { !(out & 8636021879346283486) && (out ^= 1099511627776); }
void func4d() { !(out & 6956091236936024396) && (out ^= 128); }
void func4e() { !(out & 17870283321405079551) && (out ^= 576460752303423488); }
void func4f() { !(out & 8199084751270167006) && (out ^= 70368744177664); }
void func50() { !(out & 8127027157232239070) && (out ^= 72057594037927936); }
void func51() { !(out & 6956091236936024524) && (out ^= 16); }
void func52() { !(out & 8487403091573326302) && (out ^= 4503599627370496); }
void func53() { !(out & 8646911210982211582) && (out ^= 68719476736); }
void func54() { !(out & 6956091236935958860) && (out ^= 65536); }
void func55() { !(out & 6953839437122273612) && (out ^= 2251799813685248); }
void func56() { !(out & 8636022978857911262) && (out ^= 34359738368); }
void func57() { !(out & 8646726209292457982) && (out ^= 2048); }
void func58() { !(out & 4647996427908579404) && (out ^= 256); }
void func59() { !(out & 8636021879344186334) && (out ^= 2097152); }
void func5a() { !(out & 4647996290465431624) && (out ^= 4); }
void func5b() { out |= -1; }
void func5c() { out |= -1; }
void func5d() { out |= -1; }
void func5e() { out |= -1; }
void func5f() { out |= -1; }
void func60() { out |= -1; }
void func61() { !(out & 8199155120014344670) && (out ^= 17592186044416); }
void func62() { !(out & 33685504) && (out ^= 281474976710656); }
void func63() { !(out & 8127027157232239068) && (out ^= 2); }
void func64() { !(out & 8646876026610114558) && (out ^= 8192); }
void func65() { !(out & 8636585963305292798) && (out ^= 2199023255552); }
void func66() { !(out & 6956091236936024540) && (out ^= 18014398509481984); }
void func67() { !(out & 4647996290465431628) && (out ^= 137438953472); }
void func68() { !(out & 4647996290465398792) && (out ^= 32768); }
void func69() { !(out & 8127027140052353500) && (out ^= 16384); }
void func6a() { !(out & 8636021879276553182) && (out ^= 67108864); }
void func6b() { !(out & 8646911279718465535) && (out ^= 4294967296); }
void func6c() { !(out & 8636585963171075070) && (out ^= 134217728); }
void func6d() { !(out & 8636588162328548350) && (out ^= 9007199254740992); }
void func6e() { !(out & 8487403089425842654) && (out ^= 2147483648); }
void func6f() { !(out & 18446744073708503039) && (out ^= 1048576); }
void func70() { !(out & 8645595361583289342) && (out ^= 1024); }
void func71() { !(out & 8646726209292460030) && (out ^= 274877906944); }
void func72() { !(out & 8636021879343662046) && (out ^= 524288); }
void func73() { !(out & 6974105635445506524) && (out ^= 1152921504606846976); }
void func74() { !(out & 0) && (out ^= 33554432); }
void func75() { !(out & 8646911279701688319) && (out ^= 16777216); }
void func76() { !(out & 8127027140052369884) && (out ^= 17179869184); }
void func77() { !(out & 8645595361583290366) && (out ^= 1125899906842624); }
void func78() { !(out & 8646721811245946878) && (out ^= 4398046511104); }
void func79() { !(out & 8491906691200696798) && (out ^= 144115188075855872); }
void func7a() { !(out & 8646867221658722302) && (out ^= 8796093022208); }
void func7b() { out |= -1; }
void func7c() { out |= -1; }
void func7d() { out |= -1; }
void func7e() { out |= -1; }
void func7f() { out |= -1; }

int main() {
    char input[65] = {0};
    scanf("%64s", input);
    for(int i = 0; i < 64; i++) {
        process(input[i]);
    }
    if(check()) {
        printf("Correct! DUCTF{%s}\n", input);
    } else {
        printf("Incorrect!\n");
    }
}
