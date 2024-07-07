package main

import (
	"fmt"
	"log"
	"strings"
)

var letter_map = map[rune]string{
	'A': "1000111",
	'B': "1110010",
	'C': "0011101",
	'D': "1010011",
	'E': "1010110",
	'F': "0011011",
	'G': "0110101",
	'H': "1101001",
	'I': "1001101",
	'J': "0010111",
	'K': "0011110",
	'L': "1100101",
	'M': "0111001",
	'N': "1011001",
	'O': "1110001",
	'P': "0101101",
	'Q': "0101110",
	'R': "1010101",
	'S': "1001011",
	'T': "1110100",
	'U': "1001110",
	'V': "0111100",
	'W': "0100111",
	'X': "0111010",
	'Y': "0101011",
	'Z': "1100011",
}

var figure_map = map[rune]string{
	'—':  "1000111",
	'?':  "1110010",
	':':  "0011101",
	'$':  "1010011",
	'3':  "1010110",
	'!':  "0011011",
	'&':  "0110101",
	'#':  "1101001",
	'8':  "1001101",
	'`':  "0010111",
	'(':  "0011110",
	')':  "1100101",
	'.':  "0111001",
	',':  "1011001",
	'9':  "1110001",
	'0':  "0101101",
	'1':  "0101110",
	'4':  "1010101",
	'\'': "1001011",
	'5':  "1110100",
	'7':  "1001110",
	'=':  "0111100",
	'2':  "0100111",
	'/':  "0111010",
	'6':  "0101011",
	'+':  "1100011",
}

var decode_letter_map = map[string]rune{
	"1000111": 'A',
	"1110010": 'B',
	"0011101": 'C',
	"1010011": 'D',
	"1010110": 'E',
	"0011011": 'F',
	"0110101": 'G',
	"1101001": 'H',
	"1001101": 'I',
	"0010111": 'J',
	"0011110": 'K',
	"1100101": 'L',
	"0111001": 'M',
	"1011001": 'N',
	"1110001": 'O',
	"0101101": 'P',
	"0101110": 'Q',
	"1010101": 'R',
	"1001011": 'S',
	"1110100": 'T',
	"1001110": 'U',
	"0111100": 'V',
	"0100111": 'W',
	"0111010": 'X',
	"0101011": 'Y',
	"1100011": 'Z',
}

var decode_figure_map = map[string]rune{
	"1000111": '—',
	"1110010": '?',
	"0011101": ':',
	"1010011": '$',
	"1010110": '3',
	"0011011": '!',
	"0110101": '&',
	"1101001": '#',
	"1001101": '8',
	"0010111": '`',
	"0011110": '(',
	"1100101": ')',
	"0111001": '.',
	"1011001": ',',
	"1110001": '9',
	"0101101": '0',
	"0101110": '1',
	"1010101": '4',
	"1001011": '\'',
	"1110100": '5',
	"1001110": '7',
	"0111100": '=',
	"0100111": '2',
	"0111010": '/',
	"0101011": '6',
	"1100011": '+',
}

const (
	LETTER_MODE  = "1011010"
	FIGURE_MODE  = "0110110"
	SPACE        = "1011100"
	BLANK        = "1101010"
	LINE_FEED    = "1101100"
	CARRIAGE_RET = "1111000"
)

var (
	mode = LETTER_MODE
)

func Encode(seq string) string {
	var encoded strings.Builder
	var next string

	encoded.WriteString(LETTER_MODE)

	for _, char := range seq {
		switch {
		case char == ' ':
			next = SPACE
		case char == '\n':
			next = CARRIAGE_RET
		case 'A' <= char && char <= 'Z':
			if mode != LETTER_MODE {
				encoded.WriteString(LETTER_MODE)
				mode = LETTER_MODE
			}
			next = letter_map[char]
		case 'a' <= char && char <= 'z':
			if mode != LETTER_MODE {
				encoded.WriteString(LETTER_MODE)
				mode = LETTER_MODE
			}
			upp := strings.ToUpper(string(char))
			next = letter_map[rune(upp[0])]
		case '0' <= char && char <= '9':
			next = figure_map[char]
			if next == "" {
				log.Panicln("Invalid symbol to encode", char)
			}
			if mode != FIGURE_MODE {
				encoded.WriteString(FIGURE_MODE)
				mode = FIGURE_MODE
			}
		default:
			next = figure_map[char]
			if next != "" && mode != FIGURE_MODE {
				encoded.WriteString(FIGURE_MODE)
				mode = FIGURE_MODE
			} else if next == "" {
				log.Panicf("What the heck is: %v\n", char)
			}
		}
		encoded.WriteString(next)
	}
	return encoded.String()
}

func Decode(seq string) string {
	var decoded strings.Builder
	var next rune

	mode = LETTER_MODE

	if len(seq)%7 != 0 {
		log.Panicln("Invalid encoding, aborting")
	}
	for i := 0; i < len(seq); i += 7 {
		str := seq[i : i+7]
		switch {
		case str == LETTER_MODE:
			mode = LETTER_MODE
			continue
		case str == FIGURE_MODE:
			mode = FIGURE_MODE
			continue
		case str == SPACE:
			next = ' '
		default:
			if mode == LETTER_MODE {
				next = decode_letter_map[str]
			} else {
				next = decode_figure_map[str]
			}
		}
		decoded.WriteRune(next)
	}
	return decoded.String()
}

func main() {
	// Our Flag:
	flag := "##TH3 QU0KK4'S AR3 H3LD 1N F4C1LITY #11911!"

	// Encode into Radio binary
	str := Encode(flag)
	fmt.Printf("%s\n\n", str)

	// Decode back into our flag <3
	msg := Decode(str)
	fmt.Printf("%s\n\n", msg)
}
