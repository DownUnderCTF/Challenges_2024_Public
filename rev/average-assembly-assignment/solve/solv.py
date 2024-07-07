sol = '''
# program to find the average of given inputs, where 0 indicates end of input
#
# read all input elements while summing them and counting how many there are
# INP reads into R0, so we need to store this into ACC to check if it is 0
# we will store the running sum in BAK and the count in R1
read_all_loop:
    INP           # read input into R0
    MOV R0 ACC
    JZ read_all_loop_break
    SWP
    ADD R0        # add input to running sum
    SWP
    MOV R1 ACC
    ADD 1
    MOV ACC R1
    JMP read_all_loop
# now we will do a nested for loop, with the inner loop iterating R1 times and
# subtracting one each time, and checking if the result is 0 or not. if it's 0,
# we are finished and should put the result in ACC, otherwise add 1 to the
# result. in the case where both loops hit 0 at the same time, it's a clean
# division, so we should add an extra 1 to the result
read_all_loop_break:
    MOV R1 ACC
    inner_loop:
        SUB 1
        SWP
        SUB 1
        JZ done
        SWP
        JZ inc
        JMP inner_loop
    inc:
        MOV R0 ACC
        ADD 1
        MOV ACC R0
    JMP read_all_loop_break
done:
    SWP
    JZ plusone
    MOV R0 ACC
    JMP exit
plusone:
    MOV R0 ACC
    ADD 1
exit:
'''

op_map = {
    'MOV': 'OWO',
    'ACC': 'AAA',
    'BAK': 'BBB',
    'INP': 'INP',
    'ADD': 'UWU',
    'SUB': 'QAQ',
    'SAV': 'TVT',
    'SWP': 'TOT',
    'JMP': 'WOW',
    'JZ': 'WEW',
    'JNZ': 'WAW',
    'LABEL': 'LOL',
    'NOP': 'NOP'
}

for op in op_map:
    sol = sol.replace(op, op_map[op])

print(sol)
print('EOF')
