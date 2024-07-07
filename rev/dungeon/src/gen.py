from sys import stderr
from copy import deepcopy
import random

MAZE_WIDTH = 63
MAZE_HEIGHT = 63
permutation = list(range(MAZE_WIDTH * MAZE_HEIGHT))
random.shuffle(permutation)
LOCKED_BIT = 0x10000000
MOVE_MAP = { 'N': (0,-1), 'S': (0, 1), 'E': (1, 0), 'W': (-1, 0) }
WALL_PAIRS = {'N': 'S', 'S': 'N', 'E': 'W', 'W': 'E'}

class Cell:
    def __init__(self, x, y):
        self.x, self.y = x, y
        self.walls = {'N': True, 'S': True, 'E': True, 'W': True}
        self.button_flips = []

    def has_all_walls(self):
        return all(self.walls.values())

    def knock_down_wall(self, other, wall):
        self.walls[wall] = False
        other.walls[WALL_PAIRS[wall]] = False

    def add_wall(self, wall):
        self.walls[wall] = True
        return self

    def add_all_walls(self):
        for w in WALL_PAIRS:
            self.walls[w] = True
        return self

    def add_button(self, button_flips):
        self.button_flips = button_flips
        return self

# adapted from https://github.com/Ragyan/scipython_maths/blob/master/maze/df_maze.py
class Maze:
    def __init__(self, nx, ny):
        self.nx, self.ny = nx, ny
        self.maze_map = [[Cell(x, y) for y in range(ny)] for x in range(nx)]
        self.path = []

    def cell_at(self, x, y):
        return self.maze_map[x][y]

    def find_valid_neighbours(self, cell):
        neighbours = []
        for direction, (dx, dy) in MOVE_MAP.items():
            x2, y2 = cell.x + dx, cell.y + dy
            if (0 <= x2 < self.nx) and (0 <= y2 < self.ny):
                neighbour = self.cell_at(x2, y2)
                if neighbour.has_all_walls():
                    neighbours.append((direction, neighbour))
        return neighbours

    def make_maze(self):
        n = self.nx * self.ny
        cell_stack = []
        current_cell = self.cell_at(0, 0)
        nv = 1

        while nv < n:
            neighbours = self.find_valid_neighbours(current_cell)

            if not neighbours:
                current_cell = cell_stack.pop()
                continue

            direction, next_cell = random.choice(neighbours)
            current_cell.knock_down_wall(next_cell, direction)
            cell_stack.append(current_cell)
            current_cell = next_cell
            nv += 1

    def add_random_walls(self, n):
        for _ in range(n):
            while True:
                cell = self.cell_at(random.randrange(self.nx), random.randrange(self.ny))
                if not cell.has_all_walls():
                    break
            for wall in WALL_PAIRS:
                if not cell.walls[wall]:
                    cell.add_wall(wall)
                    break

def random_inner_wall():
    allowed_walls = ['N', 'S', 'E', 'W']
    x, y = random_cell()
    if x == 0:
        allowed_walls.remove('W')
    if x == MAZE_WIDTH - 1:
        allowed_walls.remove('E')
    if y == 0:
        allowed_walls.remove('N')
    if y == MAZE_HEIGHT - 1:
        allowed_walls.remove('S')
    return (x, y), random.choice(allowed_walls)

def random_cell():
    return (random.randrange(MAZE_WIDTH), random.randrange(MAZE_HEIGHT))

def xy_to_state_num(x, y):
    if 0 <= x < MAZE_WIDTH and 0 <= y < MAZE_HEIGHT:
        return permutation[MAZE_WIDTH*y + x]
    return -1

def state_num_to_xy(n):
    n = permutation.index(n)
    return (n//MAZE_WIDTH, n%MAZE_WIDTH)

maze = Maze(MAZE_WIDTH, MAZE_HEIGHT)
maze.make_maze()

while True:
    flag_xy = random_cell()
    x, y = flag_xy
    if 0 < x < MAZE_WIDTH - 1 and 0 < y < MAZE_HEIGHT - 1:
        break
maze.cell_at(*flag_xy).add_all_walls()

for i in range(MAZE_WIDTH * MAZE_HEIGHT // 4):
    if i <= 4:
        num_flips = 2
    else:
        num_flips = random.randint(1, 3)
    buttons = []
    for _ in range(num_flips):
        xy, w = random_inner_wall()
        buttons.append((xy, w))
    if i <= 4:
        buttons.append((flag_xy, random.choice('NSWE')))
    c = random_cell()
    while c == flag_xy:
        c = random_cell()
    maze.cell_at(*c).add_button(buttons)

for x in range(MAZE_WIDTH):
    for y in range(MAZE_HEIGHT):
        c = maze.cell_at(x, y)
        for w in MOVE_MAP:
            if c.walls[w]:
                neighbour = (x+MOVE_MAP[w][0], y+MOVE_MAP[w][1])
                if xy_to_state_num(*neighbour) != -1:
                    maze.cell_at(*neighbour).walls[WALL_PAIRS[w]] = True

def get_neighbours(maze, pos):
    neighbours = []
    for mn in MOVE_MAP:
        if maze.cell_at(*pos).walls[mn]: continue
        m = MOVE_MAP[mn]
        opp = WALL_PAIRS[mn]
        new_pos = (pos[0]+m[0], pos[1]+m[1])
        if maze.cell_at(*new_pos).walls[opp]:
            continue
        if 0 <= new_pos[0] < MAZE_WIDTH and 0 <= new_pos[1] < MAZE_HEIGHT:
            neighbours.append((new_pos, mn))
    return neighbours

def reconstruct_path(parents, goal):
    path = []
    moves = []
    while goal in parents:
        moves.insert(0, parents[goal][1])
        path.insert(0, goal)
        goal = parents[goal][0]
    path.insert(0, goal)
    return path, ''.join(moves)

def bfs(maze, start, goal):
    visited = {start}
    parents = {}
    Q = [start]
    while len(Q):
        v = Q.pop(0)
        if v == goal:
            return reconstruct_path(parents, goal)
        for neighbour, move in get_neighbours(maze, v):
            if neighbour in visited:
                continue
            visited.add(neighbour)
            parents[neighbour] = (v, move)
            Q.append(neighbour)
    return None, None

def solve_maze(maze, start, goal):
    for y in range(MAZE_HEIGHT):
        for x in range(MAZE_WIDTH):
            c = maze.cell_at(x, y)
            if not any(b == goal and maze.cell_at(*b).walls[w] for b, w in c.button_flips): continue

            _, first_leg = bfs(maze, start, (x, y))
            if first_leg is None: continue

            maze_copy = deepcopy(maze)

            for b, w in c.button_flips:
                maze_copy.cell_at(*b).walls[w] = not maze_copy.cell_at(*b).walls[w]
                b_opp = (b[0] + MOVE_MAP[w][0], b[1] + MOVE_MAP[w][1])
                maze_copy.cell_at(*b_opp).walls[WALL_PAIRS[w]] = not maze_copy.cell_at(*b_opp).walls[WALL_PAIRS[w]]
            _, second_leg = bfs(maze_copy, (x, y), goal)
            if second_leg is None: continue

            return (first_leg + 'p' + second_leg).replace('W', 'a').replace('S', 's').replace('E', 'd').replace('N', 'w')
    return False

print('solvable?', solve_maze(maze, (0, 0), flag_xy), file=stderr)

def wall_to_2bit(w):
    if w == 'W':
        return 0
    if w == 'N':
        return 1
    if w == 'E':
        return 2
    if w == 'S':
        return 3
    assert False, 'should not reach this'

def cell_to_state_struct(cell: Cell):
    n = xy_to_state_num(cell.x, cell.y)
    left = xy_to_state_num(cell.x - 1, cell.y)
    up = xy_to_state_num(cell.x, cell.y - 1)
    right = xy_to_state_num(cell.x + 1, cell.y)
    down = xy_to_state_num(cell.x, cell.y + 1)
    if cell.walls['N']:
        up |= LOCKED_BIT
    if cell.walls['S']:
        down |= LOCKED_BIT
    if cell.walls['W']:
        left |= LOCKED_BIT
    if cell.walls['E']:
        right |= LOCKED_BIT
    action_func = None
    if len(cell.button_flips) == 1:
        n_other = xy_to_state_num(*cell.button_flips[0][0])
        w = wall_to_2bit(cell.button_flips[0][1])
        m = MOVE_MAP[cell.button_flips[0][1]]
        n_other_opp = (cell.button_flips[0][0][0]+m[0], cell.button_flips[0][0][1]+m[1])
        n_other_opp = xy_to_state_num(*n_other_opp)
        action_func = f'ACTION_WALL_FLIP1({n}, {n_other}, {n_other_opp}, {w})'
    elif len(cell.button_flips) == 2:
        n_other1 = xy_to_state_num(*cell.button_flips[0][0])
        w1 = wall_to_2bit(cell.button_flips[0][1])
        m1 = MOVE_MAP[cell.button_flips[0][1]]
        n_other_opp1 = (cell.button_flips[0][0][0]+m1[0], cell.button_flips[0][0][1]+m1[1])
        n_other_opp1 = xy_to_state_num(*n_other_opp1)
        n_other2 = xy_to_state_num(*cell.button_flips[1][0])
        w2 = wall_to_2bit(cell.button_flips[1][1])
        m2 = MOVE_MAP[cell.button_flips[1][1]]
        n_other_opp2 = (cell.button_flips[1][0][0]+m2[0], cell.button_flips[1][0][1]+m2[1])
        n_other_opp2 = xy_to_state_num(*n_other_opp2)
        action_func = f'ACTION_WALL_FLIP2({n}, {n_other1}, {n_other_opp1}, {w1}, {n_other2}, {n_other_opp2}, {w2})'
    elif len(cell.button_flips) == 3:
        n_other1 = xy_to_state_num(*cell.button_flips[0][0])
        w1 = wall_to_2bit(cell.button_flips[0][1])
        m1 = MOVE_MAP[cell.button_flips[0][1]]
        n_other_opp1 = (cell.button_flips[0][0][0]+m1[0], cell.button_flips[0][0][1]+m1[1])
        n_other_opp1 = xy_to_state_num(*n_other_opp1)
        n_other2 = xy_to_state_num(*cell.button_flips[1][0])
        n_other2 = xy_to_state_num(*cell.button_flips[1][0])
        w2 = wall_to_2bit(cell.button_flips[1][1])
        m2 = MOVE_MAP[cell.button_flips[1][1]]
        n_other_opp2 = (cell.button_flips[1][0][0]+m2[0], cell.button_flips[1][0][1]+m2[1])
        n_other_opp2 = xy_to_state_num(*n_other_opp2)
        n_other3 = xy_to_state_num(*cell.button_flips[2][0])
        w3 = wall_to_2bit(cell.button_flips[2][1])
        m3 = MOVE_MAP[cell.button_flips[2][1]]
        n_other_opp3 = (cell.button_flips[2][0][0]+m3[0], cell.button_flips[2][0][1]+m3[1])
        n_other_opp3 = xy_to_state_num(*n_other_opp3)
        action_func = f'ACTION_WALL_FLIP3({n}, {n_other1}, {n_other_opp1}, {w1}, {n_other2}, {n_other_opp2}, {w2}, {n_other3}, {n_other_opp3}, {w3})'
    action_func_name = '0'
    if action_func:
        action_func_name = f'action_func_{n}'
    if flag_xy == (cell.x, cell.y):
        return f'{{ .left_room = {left}, .up_room = {up}, .right_room = {right}, .down_room = {down}, .action_func = get_flag }}', f'void {action_func_name}();', action_func
    return f'{{ .left_room = {left}, .up_room = {up}, .right_room = {right}, .down_room = {down}, .action_func = {action_func_name} }}', f'void {action_func_name}();', action_func

def preprocess(infile, maze):
    dat = open(infile, 'r').read()
    rep = 'state_t MAZE[MAZE_WIDTH * MAZE_HEIGHT] = {X};'
    md = []
    fns = []
    fncs = []
    for y in range(MAZE_HEIGHT):
        for x in range(MAZE_WIDTH):
            c = maze.cell_at(x, y)
            a, fn, f = cell_to_state_struct(c)
            if f:
                fns.append(fn)
                fncs.append(f)
            md.append(a)
    md_permed = ['X']*len(permutation)
    for i, p in enumerate(permutation):
        md_permed[p] = md[i]
    rep = '\n'.join(fns) + '\n' + rep.replace('X', ','.join(md_permed)) + '\n' + '\n'.join(fncs)
    start_room = xy_to_state_num(0, 0)
    flag_room = xy_to_state_num(*flag_xy)
    return dat.replace('state_t MAZE[MAZE_WIDTH * MAZE_HEIGHT] = {};', rep).replace('#define START_ROOM 0', f'#define START_ROOM {start_room}').replace('#define FLAG_ROOM 42', f'#define FLAG_ROOM {flag_room}').replace('#define MAZE_WIDTH 0', f'#define MAZE_WIDTH {MAZE_WIDTH}').replace('#define MAZE_HEIGHT 0', f'#define MAZE_HEIGHT {MAZE_HEIGHT}')

print(preprocess('./dungeon.c', maze))
