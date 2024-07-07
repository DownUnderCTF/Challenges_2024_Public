DNAdecay
============

`dna.rb` is a ruby script that has been obfuscated using https://github.com/mame/doublehelix and had a random characters replaced with space (0x20) characters.

This folder contains two methods of solving this challenge:
1. `solve.rb` - a completely automated solution which will output only variations that are valid strings. It's then on the human to chose which vaild string is most resonably going to be the flag.

    ```bash
    ruby solve.rb > candidates.txt # Will show progress in stderr
    ```

2. `solve_manual.rb` - a semi-manual script which goes *most* of the way, but relies on the human to figure out the last 8 sequences by bruteforce. Using error messages as clues, a human can do this in about 10 minutes.

## Using solve_manual.rb

If you haven't realized yet, `solve.py` is just the first part of solve.rb.

```bash
ruby solve.rb > candidate.rb
```

Then open `candidate.rb` in your favourite text editor and find the lines with `missing`. The first should be line 79.

Attempt to run `candidate.rb` (yes, without changing it).

```bash
ruby candidate.rb
```

You'll get an error with a parital flag:

```
/~/.gem/ruby/2.6.0/gems/doublehelix-1.0/lib/doublehelix.rb:8:in `eval': (eval):1: unterminated string meets end of file (SyntaxError)
puts"DUCTF{7H3_Mit0
                    ^
        from /~/.gem/ruby/2.6.0/gems/doublehelix-1.0/lib/doublehelix.rb:8:in `block in <top (required)>'
argghhh.txt:79:in `<main>': undefined local variable or method `missing' for main:Object (NameError)
```

Go back to your text editor and change all the `missing` to `AT #####` then run it. You should get something like:

```
DUCTF{7H3_Mit0cHOndRi415O7he_P0wEr_HoUpE_ofODA_C3L
                                                  }
```

You might realise this flag is referencing the meme `The Mitochondria is the power house of the cell` but with L33T speak and spongebob capitalization (idk what else to call it).

Knowing this, let's go back and try to bruteforce the missing (now marked by `#####`) to get some more reasonable results. Let's do them working backwards.

Changing the last missing line to `GC` gives:
```
DUCTF{7H3_Mit0cHOndRi415O7he_P0wEr_HoUpE_ofODA_C3LL}
```

Changing the second last missing line to `GC` gives:
```
DUCTF{7H3_Mit0cHOndRi415O7he_P0wEr_HoUpE_of_DA_C3LL}
```

Changing the next missing line to `TA` gives:
```
DUCTF{7H3_Mit0cHOndRi415O7he_P0wEr_HoUsE_of_DA_C3LL}
```

Changing the next missing line to `GC` gives:
```
DUCTF{7H3_Mit0cHOndRi415_7he_P0wEr_HoUsE_of_DA_C3LL}
```

Changing the next two missing lines to `GC` and `GC` gives:
```
DUCTF{7H3_Mit0cHOndRi4_15_7he_P0wEr_HoUsE_of_DA_C3LL}
```

We can continue bruteforcing, but we'll notice we're just making the flag *more* intelligable.