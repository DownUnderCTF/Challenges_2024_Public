package main

import (
	"log"
	"math"
	"math/big"
	"os"
	"strings"
)

var (
	opMoveRight = "00" // >
	opMoveLeft  = "01" // <
	opIncrement = "02" // +
	opDecrement = "10" // -
	opWrite     = "11" // .
	opRead      = "12" // ,
	opLoopStart = "20" // [
	opLoopEnd   = "21" // ]
)

func repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

var G [256][256]string

func init() {
	// initial state for G[x][y]: go from x to y using +s or -s.
	for x := 0; x < 256; x++ {
		for y := 0; y < 256; y++ {
			delta := y - x
			if delta > 128 {
				delta -= 256
			}
			if delta < -128 {
				delta += 256
			}

			if delta >= 0 {
				G[x][y] = repeat(opIncrement, delta)
			} else {
				G[x][y] = repeat(opDecrement, -delta)
			}
		}
	}

	// keep applying rules until we can't find any more shortenings
	iter := true
	for iter {
		iter = false

		// multiplication by n/d
		for x := 0; x < 256; x++ {
			for n := 1; n < 40; n++ {
				for d := 1; d < 40; d++ {
					j := x
					y := 0
					for i := 0; i < 256; i++ {
						if j == 0 {
							break
						}
						j = (j - d + 256) & 255
						y = (y + n) & 255
					}
					if j == 0 {
						s := opLoopStart + repeat(opDecrement, d) + opMoveRight + repeat(opIncrement, n) + opMoveLeft + opLoopEnd + opMoveRight
						if len(s) < len(G[x][y]) {
							G[x][y] = s
							iter = true
						}
					}

					j = x
					y = 0
					for i := 0; i < 256; i++ {
						if j == 0 {
							break
						}
						j = (j + d) & 255
						y = (y - n + 256) & 255
					}
					if j == 0 {
						s := opLoopStart + repeat(opIncrement, d) + opMoveRight + repeat(opDecrement, n) + opMoveLeft + opLoopEnd + opMoveRight
						if len(s) < len(G[x][y]) {
							G[x][y] = s
							iter = true
						}
					}
				}
			}
		}

		// combine number schemes
		for x := 0; x < 256; x++ {
			for y := 0; y < 256; y++ {
				for z := 0; z < 256; z++ {
					if len(G[x][z])+len(G[z][y]) < len(G[x][y]) {
						G[x][y] = G[x][z] + G[z][y]
						iter = true
					}
				}
			}
		}
	}
}

func generate(s []byte) string {
	out := strings.Builder{}
	var lastc byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		a := G[lastc][c]
		b := G[0][c]
		if len(a) <= len(b) {
			out.WriteString(a)
		} else {
			out.WriteString(opMoveRight + b)
		}
		out.WriteString(opWrite)
		lastc = c
	}
	return out.String()
}

func main() {
	buf := make([]byte, int(math.Pow(3, 8)))
	n, err := os.Stdin.Read(buf)
	if err != nil {
		log.Fatalf("%s", err)
	}

	buf = buf[:n]

	val := generate(buf)

	enc := new(big.Int)

	var ok bool
	enc, ok = enc.SetString(val, 3)
	if !ok {
		log.Fatalf("failed to encode")
	}

	if _, err := os.Stdout.Write(enc.Bytes()); err != nil {
		log.Fatalf("%s", err)
	}
}
