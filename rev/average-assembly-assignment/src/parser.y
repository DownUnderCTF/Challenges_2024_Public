%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define MAX_INS_CNT 36

int yylex();
void yyerror(const char *s) {
    fprintf(stderr, "Error: %s\n", s);
}

typedef struct Instruction *instruction_t;
typedef struct {
    char *opcode;
    char *arg1;
    char *arg2;
    instruction_t next;
} Instruction;

Instruction *program = NULL;
Instruction *last_instruction = NULL;
size_t ins_cnt = 0;

void add_instruction(char *opcode, char *arg1, char *arg2) {
    ins_cnt++;
    if(ins_cnt >= MAX_INS_CNT) {
        printf("I ain't reading all that\n");
        exit(1);
    }
    Instruction *inst = (Instruction *)malloc(sizeof(Instruction));
    inst->opcode = opcode;
    inst->arg1 = arg1;
    inst->arg2 = arg2;
    inst->next = NULL;

    if (last_instruction == NULL) {
        program = inst;
    } else {
        last_instruction->next = inst;
    }
    last_instruction = inst;
}

%}

%union {
 char* num;
 char* str;
}
%token <str> MOV ADD SUB SAV SWP JMP JZ JNZ NOP ACC BAK IDENTIFIER GPR INP
%token <num> NUMBER
%token COLON

%%

program:
    | program statement
    ;

statement:
      MOV NUMBER ACC             { add_instruction("OWO", $2, "AAA"); }
    | MOV NUMBER BAK             { add_instruction("OWO", $2, "BBB"); }
    | MOV NUMBER GPR             { add_instruction("OWO", $2, $3); }
    | MOV ACC GPR                { add_instruction("OWO", "AAA", $3); }
    | MOV BAK GPR                { add_instruction("OWO", "BBB", $3); }
    | MOV GPR ACC                { add_instruction("OWO", $2, "AAA"); }
    | MOV GPR BAK                { add_instruction("OWO", $2, "BBB"); }
    | MOV GPR GPR                { add_instruction("OWO", $2, $3); }
    | MOV NUMBER NUMBER          { add_instruction("OWO", $2, $3); }
    | MOV IDENTIFIER IDENTIFIER  { add_instruction("OWO", $2, $3); }
    | INP                        { add_instruction("INP", NULL, NULL); }
    | ADD NUMBER                 { add_instruction("UWU", $2, NULL); }
    | ADD BAK                    { add_instruction("UWU", "BBB", NULL); }
    | ADD GPR                    { add_instruction("UWU", $2, NULL); }
    | SUB NUMBER                 { add_instruction("QAQ", $2, NULL); }
    | SUB BAK                    { add_instruction("QAQ", "BBB", NULL); }
    | SUB GPR                    { add_instruction("QAQ", $2, NULL); }
    | SAV                        { add_instruction("TVT", NULL, NULL); }
    | SWP                        { add_instruction("TOT", NULL, NULL); }
    | JMP IDENTIFIER             { add_instruction("WOW", $2, NULL); }
    | JZ IDENTIFIER              { add_instruction("WEW", $2, NULL); }
    | JNZ IDENTIFIER             { add_instruction("WAW", $2, NULL); }
    | IDENTIFIER COLON           { add_instruction("LOL", $1, NULL); }
    | NOP                        { add_instruction("NOP", NULL, NULL); }
    ;

%%


int execute_program(unsigned char input[21]) {
    Instruction *current = program;
    int inp_cnt = 0;
    int acc = 0;
    int bak = 0;
    int registers[2] = {0};
    Instruction *labels[100];
    int label_count = 0;

    while (current != NULL) {
        if (strcmp(current->opcode, "LOL") == 0) {
            labels[label_count++] = current;
        }
        current = current->next;
    }

    current = program;
    while (current != NULL) {
        if (strcmp(current->opcode, "OWO") == 0) {
            if (strcmp(current->arg2, "AAA") == 0) {
                if (strcmp(current->arg1, "AAA") == 0) {
                    acc = acc;
                } else if (strcmp(current->arg1, "BBB") == 0) {
                    acc = bak;
                } else if (current->arg1[0] == 'R') {
                    acc = registers[current->arg1[1] - '0'];
                } else {
                    acc = atoi(current->arg1);
                }
            } else if (strcmp(current->arg2, "BBB") == 0) {
                if (strcmp(current->arg1, "AAA") == 0) {
                    bak = acc;
                } else if (strcmp(current->arg1, "BBB") == 0) {
                    bak = bak;
                } else if (current->arg1[0] == 'R') {
                    bak = registers[current->arg1[1] - '0'];
                } else {
                    bak = atoi(current->arg1);
                }
            } else if (current->arg2[0] == 'R') {
                int d = current->arg2[1] - '0';
                if (strcmp(current->arg1, "AAA") == 0) {
                    registers[d] = acc;
                } else if (strcmp(current->arg1, "BBB") == 0) {
                    registers[d] = bak;
                } else if (current->arg1[0] == 'R') {
                    registers[d] = registers[current->arg1[1] - '0'];
                } else {
                    registers[d] = atoi(current->arg1);
                }
            }
        } else if (strcmp(current->opcode, "UWU") == 0) {
            if(strcmp(current->arg1, "BBB") == 0) {
                acc += bak;
            } else if(current->arg1[0] == 'R') {
                acc += registers[current->arg1[1] - '0'];
            } else {
                acc += atoi(current->arg1);
            }
        } else if (strcmp(current->opcode, "QAQ") == 0) {
            if(strcmp(current->arg1, "BBB") == 0) {
                acc -= bak;
            } else if(current->arg1[0] == 'R') {
                acc -= registers[current->arg1[1] - '0'];
            }
            else {
                acc -= atoi(current->arg1);
            }
        } else if (strcmp(current->opcode, "TVT") == 0) {
            bak = acc;
        } else if (strcmp(current->opcode, "TOT") == 0) {
            int temp = acc;
            acc = bak;
            bak = temp;
        } else if (strcmp(current->opcode, "WOW") == 0) {
            for (int i = 0; i < label_count; i++) {
                if (strcmp(labels[i]->arg1, current->arg1) == 0) {
                    current = labels[i];
                    break;
                }
            }
        } else if (strcmp(current->opcode, "WEW") == 0) {
            if (acc == 0) {
                for (int i = 0; i < label_count; i++) {
                    if (strcmp(labels[i]->arg1, current->arg1) == 0) {
                        current = labels[i];
                        break;
                    }
                }
            }
        } else if (strcmp(current->opcode, "WAW") == 0) {
            if (acc != 0) {
                for (int i = 0; i < label_count; i++) {
                    if (strcmp(labels[i]->arg1, current->arg1) == 0) {
                        current = labels[i];
                        break;
                    }
                }
            }
        } else if (strcmp(current->opcode, "INP") == 0) {
            if(inp_cnt < 21) {
                registers[0] = input[inp_cnt++];
            }
        } else if (strcmp(current->opcode, "NOP") == 0) {
        }

        current = current->next;
    }

    return acc;
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    printf("Please submit your working below the line:\n");
    printf("------------------------------------------\n");
    char* buf = (char*)malloc(0x100);
    char* line = NULL;
    size_t total_len = 0;
    size_t len = 0;
    size_t read;
    while ((read = getline(&line, &len, stdin)) != -1) {
        if(strncmp(line, "EOF", 3) == 0) break;
        char *temp = realloc(buf, total_len + read + 1);
        if (temp == NULL) {
            free(buf);
            free(line);
            exit(1);
        }
        buf = temp;
        strcpy(buf + total_len, line);
        total_len += read;
    }
    yy_scan_string(buf);
    int p = yyparse();
    if(p) {
        printf("Error!\n");
        exit(1);
    }
    unsigned char input[21] = {0};
    int acc, ans, l;
    for(int i = 0; i < 100; i++) {
        memset(input, 0, 20);
        getrandom(&l, 1, 0);
        l = (l % 19) + 1;
        getrandom(input, l, 0);
        for(int j = 0; j < l; j++) {
            input[j] |= 1;
        }
        acc = execute_program(input);
        ans = 0;
        for(int j = 0; j < l; j++) {
            ans += input[j];
        }
        ans /= l;
        if(acc != ans) {
            printf("Wrong!\n");
            exit(1);
        }
    }
    char FLAG[0x100] = {};
    FILE* f = fopen("flag.txt", "r");
    fread(FLAG, 1, 0x100, f);
    printf("%s\n", FLAG);
    return 0;
}
