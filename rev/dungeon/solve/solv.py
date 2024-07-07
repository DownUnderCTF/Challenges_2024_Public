import capstone
from copy import deepcopy
from tqdm import tqdm

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

START_ROOM = 1251
FLAG_ROOM = 1551
MAZE_DATA_START = 0x27080
MAZE_DATA_END = 0x3e498
MAZE_VA_START = 0x428080
MAZE_VA_END = 0x43f498
LOCKED_BIT = 0x10000000
WALL_PAIRS = {'N': 'S', 'S': 'N', 'E': 'W', 'W': 'E'}

class Cell:
    def __init__(self, left, up, right, down, button_flips):
        self.neighbours = {
            'W': left,
            'N': up,
            'E': right,
            'S': down
        }
        self.button_flips = button_flips

def wall_from_2bit(b):
    return 'WNES'[b]

BINARY_DATA = open('../publish/dungeon', 'rb').read()

def disasm_button_flips(func_addr):
    if func_addr == 0: return []
    ins = list(cs.disasm(BINARY_DATA[func_addr - 0x400000:], 0))
    button_flips = []
    for instruction in ins:
        # print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
        if instruction.mnemonic == 'lea':
            op_str = instruction.op_str
            offset = int(op_str.split('rip + ')[1].split(']')[0], 16)
            offset += func_addr + instruction.address - 1
            offset += 8
            # print(hex(func_addr), offset)
            assert MAZE_VA_START <= offset <= MAZE_VA_END
            offset -= MAZE_VA_START
            target = offset//24
            wall = (offset%24)//4
            assert 0 <= wall <= 3
            button_flips.append((target, wall_from_2bit(wall)))
        if instruction.mnemonic == 'ret':
            break
    return button_flips

def parse_maze_data(maze_data):
    cells_raw = [maze_data[i:i+24] for i in range(0, len(maze_data), 24)]
    cells = []
    for i, cell in tqdm(list(enumerate(cells_raw))):
        left = int.from_bytes(cell[0:4], 'little')
        up = int.from_bytes(cell[4:8], 'little')
        right = int.from_bytes(cell[8:12], 'little')
        down = int.from_bytes(cell[12:16], 'little')
        action_func = int.from_bytes(cell[16:24], 'little')
        if i == FLAG_ROOM:
            cells.append(Cell(left, up, right, down, []))
        else:
            cells.append(Cell(left, up, right, down, disasm_button_flips(action_func)))
    return cells

maze_data = BINARY_DATA[MAZE_DATA_START:MAZE_DATA_END]
cells = parse_maze_data(maze_data)

def get_neighbours(cells, pos):
    return [(n, mv) for mv, n in cells[pos].neighbours.items() if n & LOCKED_BIT == 0]

def reconstruct_path(parents, goal):
    path = []
    moves = []
    while goal in parents:
        moves.insert(0, parents[goal][1])
        path.insert(0, goal)
        goal = parents[goal][0]
    path.insert(0, goal)
    return path, ''.join(moves)

def bfs(cells, start, goal):
    visited = {start}
    parents = {}
    Q = [start]
    while len(Q):
        v = Q.pop(0)
        if v == goal:
            return reconstruct_path(parents, goal)
        for neighbour, move in get_neighbours(cells, v):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            parents[neighbour] = (v, move)
            Q.append(neighbour)
    return None, None

def solve_maze(cells, start, goal):
    for i in range(len(cells)):
        c = cells[i] 
        if not any(b == goal and cells[b].neighbours[w] & LOCKED_BIT for b, w in c.button_flips): continue

        _, first_leg = bfs(cells, start, i)
        if first_leg is None: continue

        cells_copy = deepcopy(cells)

        for b, w in c.button_flips:
            cells_copy[b].neighbours[w] ^= LOCKED_BIT
        _, second_leg = bfs(cells_copy, i, goal)
        if second_leg is None: continue

        return (first_leg + 'p' + second_leg).replace('W', 'a').replace('S', 's').replace('E', 'd').replace('N', 'w')
    return False

sol = solve_maze(cells, START_ROOM, FLAG_ROOM)
assert sol

print('\n'.join(list(sol))) # paste into ssh connection

# from pwn import *
# conn = process(['../publish/dungeon'], cwd='../src/')
# for s in sol:
#     conn.sendline(s)
# conn.sendline('p')
# conn.interactive()
