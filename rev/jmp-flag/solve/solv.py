import capstone

FUNCS_START = 0x1300

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

BINARY = open('../publish/jmp_flag', 'rb').read()

funcs = [-1] * 128
offset = FUNCS_START
for i in range(128):
    ins = list(cs.disasm(BINARY[offset:offset+128], 0))
    offset += 128
    if ins[6].mnemonic == 'ret':
        continue
    for instruction in ins:
        if instruction.mnemonic in ['and', 'movabs']:
            mask = int(instruction.op_str.split()[-1], 16)
            funcs[i] = mask
            break
    else:
        print('weird', chr(i))
funcs[ord('t')] = 0
flag = ['~'] * 64
for i in range(128):
    if funcs[i] == -1: continue
    flag[bin(funcs[i]).count('1')] = chr(i)
print(''.join(flag))
