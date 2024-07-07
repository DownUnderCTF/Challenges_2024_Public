
%{
#include "parser.tab.h"
%}

%option noyywrap

%%

"OWO"        { return MOV; }
"UWU"        { return ADD; }
"QAQ"        { return SUB; }
"TVT"        { return SAV; }
"TOT"        { return SWP; }
"WOW"        { return JMP; }
"WEW"         { return JZ; }
"WAW"        { return JNZ; }
"NOP"        { return NOP; }
"AAA"        { return ACC; }
"BBB"        { return BAK; }
"INP"        { return INP; }
[0-9]+       { yylval.num = strdup(yytext); return NUMBER; }
[R][0-1]     { yylval.str = strdup(yytext); return GPR; }
[a-zA-Z_][a-zA-Z0-9_]*   { yylval.str = strdup(yytext); return IDENTIFIER; }
":"          { return COLON; }
[ \t\n]+     { }
#.*          { }
.            { printf("Unexpected character: %s\n", yytext); }

%%

