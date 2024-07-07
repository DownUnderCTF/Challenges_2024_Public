# The Door

This challenge requires you to guess a 32-bit code to release the flag.
It consists of shift registers which you can shift data through, which will go through to a circuit to check equality to the secret code.

A naive approach would be to guess 2^32 codes, clocking 32 times per, requiring 2^40 clocks to happen. At 2MHz as laid out in the schematic, thats 7 days - no can do.

A better approach is to use a de Brujin sequence, which exploits the fact we are using shift registers to allow us to clock once per guess.
Take a reduced example of just 3 bits, for a debrujin sequence:

```
Sequence: 0 0 0 1 0 1 1 1 0 0
          -------------------
Guesses:  0 0 0
            0 0 1
              0 1 0
                1 0 1
                  0 1 1
                    1 1 1
                      1 1 0
                        1 0 0
```

This reduced us from guessing 3 \* 2^3 = 24 bits, down to just 10 bits.
We can apply the same technique to guessing our random code, getting us down to 2^32 bits, at 2MHz is 35 minutes - much better.

Given the context of a door and probably a key fob, these are usually configured with DIP switches which people usually only flip a few of.
We can use this information to try smaller codes first, e.g. all `0`s, single `1`'s, two `1`'s etc, in our codes.

We can't store a 2^32-sized code in the flash, its too large, so we have to generate this sequence at runtime, and then transmit it out.

The provided solution in [solve.c](solve.c) uses this approach, but bit-bangs data. A more refined solution would use PIO to transmit data at a higher rate.
