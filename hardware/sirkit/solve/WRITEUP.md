# Sitkit

This is a PCB reversing challenge, given the gerber/manufacturing files, and a bill of materials.

The idea here is to extract the netlist contained within the gerber files and use this to reverse engineer this circuit board.
What makes this tricky is some of the gates are unknown.

The bill of materials provided has its designators removed, but we know there are 15 74LS40 quad-input NAND gates. These chips have pins 3 and 11 disconnected, and thus are easily identifiable.

Next are the four 74LS04 not-gates. These can be identified as both pins 1 and 3 are used as inputs, rather than an output one being an output.

From here, the system can be solved using a tool such as Z3 for all `byte_num` and `byte_guess` which give a `guess_valid`.
