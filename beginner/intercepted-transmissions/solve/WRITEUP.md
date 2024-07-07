Pix's Writeup
============

The flavour text gives us the biggest hint of what we're going to be doing with that string of 
binary inside the `encoding` file.

CCIR476 is an older radio encoding that ensures transmission of data, specifically it uses 7 bits 
instead of the previous 5 bit code used in ITA2. Four of those bits represent markers, and the rest 
(3) are spaces allowing for error correction similar to Huffman encoding!

Importantly this means there are only 35 possible code points, which are mapped at the bottom in 
the encoding rules!

All an enterprising individual needs to do in order to decode this encoding is take the binary stream 
apart in chunks of 7 at a time and converting it to relevant LETTER or FIGURE.

This also means that in order to use both letters AND symbols, they must keep track of the mode that 
has been transmitted and if its been changed by checking first for one of the following:

``1011010        ↓ LTRS (Letter shift)``
``0110110        ↑ FIGS (Figure shift)``

Once the mode is set, decode the corresponding value and you eventually get the string:

`##TH3 QU0KK4BELLS AR3 H3LD 1N F4C1LITY #11911!`

I hope you learnt something! <3



### Encoding Rules:
Encoding | hex | letter | symbol 

1000111     47     A         — 
1110010     72     B         ? 
0011101     1D     C         : 
1010011     53     D         5 
1010110     56     E         3 
0011011     1B     F         4 
0110101     35     G         4 
1101001     69     H         4 
1001101     4D     I         8 
0010111     17     J         BE
0011110     1E     K         ( 
1100101     65     L         ) 
0111001     39     M         . 
1011001     59     N         , 
1110001     71     0         9 
0101101     2D     P         0 
0101110     2E     Q         1 
1010101     55     R         4 
1001011     4B     S         ' 
1110100     74     T         5 
1001110     4E     U         7 
0111100     3C     V         = 
0100111     27     W         2 
0111010     3A     X         / 
0101011     2B     Y         6 
1100011     63     Z         + 
1111000     78     ← CR (Carriage return)
1101100     6C     ≡ LF (Line feed)
1011010     5A     ↓ LTRS (Letter shift)
0110110     36     ↑ FIGS (Figure shift)
1011100     5C     SP (Space)
1101010     6A     BLK (Blank) 
