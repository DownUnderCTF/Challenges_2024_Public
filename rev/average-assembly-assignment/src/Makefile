CC = gcc
FLEX = flex
BISON = bison

CFLAGS = -Wall -g

LEX_FILE = lexer.l
BISON_FILE = parser.y
BISON_HEADER = parser.tab.h
LEX_OUTPUT = lex.yy.c
BISON_OUTPUT = parser.tab.c
OUTPUT_EXEC = aaa

all: $(OUTPUT_EXEC)

$(OUTPUT_EXEC): $(LEX_OUTPUT) $(BISON_OUTPUT)
	$(CC) $(CFLAGS) -o $@ $^

$(LEX_OUTPUT): $(LEX_FILE) $(BISON_HEADER)
	$(FLEX) $(LEX_FILE)

$(BISON_OUTPUT) $(BISON_HEADER): $(BISON_FILE)
	$(BISON) -d $(BISON_FILE)

clean:
	rm -f $(LEX_OUTPUT) $(BISON_OUTPUT) $(BISON_HEADER) $(OUTPUT_EXEC)

.PHONY: clean
