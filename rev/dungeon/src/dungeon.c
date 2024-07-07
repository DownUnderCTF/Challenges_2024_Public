#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAZE_WIDTH 0
#define MAZE_HEIGHT 0
#define START_ROOM 0
#define FLAG_ROOM 42
#define LOCKED_BIT 0x10000000
#define ACTION_WALL_FLIP1(n, n_other, n_other_opp, w) \
    void action_func_##n() { \
        int* p = ((int*)&MAZE[n_other]) + w; \
        *p ^= LOCKED_BIT; \
        if(n_other_opp != -1) { \
            int* p1 = ((int*)&MAZE[n_other_opp]) + ((w + 2) % 4); \
            *p1 ^= LOCKED_BIT; \
        } \
    }
#define ACTION_WALL_FLIP2(n, n_other1, n_other1_opp, w1, n_other2, n_other2_opp, w2) \
    void action_func_##n() { \
        int* p1 = ((int*)&MAZE[n_other1]) + w1; \
        *p1 ^= LOCKED_BIT; \
        int* p2 = ((int*)&MAZE[n_other2]) + w2; \
        *p2 ^= LOCKED_BIT; \
        if(n_other1_opp != -1) { \
            int* p3 = ((int*)&MAZE[n_other1_opp]) + ((w1 + 2) % 4); \
            *p3 ^= LOCKED_BIT; \
        } \
        if(n_other2_opp != -1) { \
            int* p4 = ((int*)&MAZE[n_other2_opp]) + ((w2 + 2) % 4); \
            *p4 ^= LOCKED_BIT; \
        } \
    }
#define ACTION_WALL_FLIP3(n, n_other1, n_other1_opp, w1, n_other2, n_other2_opp, w2, n_other3, n_other3_opp, w3) \
    void action_func_##n() { \
        int* p1 = ((int*)&MAZE[n_other1]) + w1; \
        *p1 ^= LOCKED_BIT; \
        int* p2 = ((int*)&MAZE[n_other2]) + w2; \
        *p2 ^= LOCKED_BIT; \
        int* p3 = ((int*)&MAZE[n_other3]) + w3; \
        *p3 ^= LOCKED_BIT; \
        if(n_other1_opp != -1) { \
            int* p4 = ((int*)&MAZE[n_other1_opp]) + ((w1 + 2) % 4); \
            *p4 ^= LOCKED_BIT; \
        } \
        if(n_other2_opp != -1) { \
            int* p5 = ((int*)&MAZE[n_other2_opp]) + ((w2 + 2) % 4); \
            *p5 ^= LOCKED_BIT; \
        } \
        if(n_other3_opp != -1) { \
            int* p6 = ((int*)&MAZE[n_other3_opp]) + ((w3 + 2) % 4); \
            *p6 ^= LOCKED_BIT; \
        } \
    }

typedef struct {
    int left_room;
    int up_room;
    int right_room;
    int down_room;
    void (*action_func)(void);
} state_t;
void get_flag();
state_t MAZE[MAZE_WIDTH * MAZE_HEIGHT] = {};

typedef struct {
    int room;
    int curr_pos;
    int locked;
} game_state_t;

void get_flag() {
    char flag[0x100];
    FILE* flag_file = fopen("flag.txt", "r");
    if(!flag_file) {
        printf("Error opening flag.txt :(\n");
        exit(1);
    }
    fread(flag, 1, 0x100, flag_file);
    printf("%s\n", flag);
    exit(0);
}

void render(game_state_t* game_state) {
    printf("%c[2J", 27);
    char framebuffer[10][15] = {
        {'+','-','-','-','-','-','-','^','-','-','-','-','-','-','+'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'<',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','>'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'|',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','|'},
        {'+','-','-','-','-','-','-','v','-','-','-','-','-','-','+'},
    };
    int player_x = 0;
    int player_y = 0;
    if(game_state->curr_pos == 0) {
        player_x = 1;
        player_y = 4;
    } else if(game_state->curr_pos == 1) {
        player_x = 7;
        player_y = 1;
    } else if(game_state->curr_pos == 2) {
        player_x = 13;
        player_y = 4;
    } else if(game_state->curr_pos == 3) {
        player_x = 7;
        player_y = 8;
    }
    framebuffer[player_y][player_x] = 'P';
    for(int y = 0; y < 10; y++) {
        for(int x = 0; x < 15; x++) {
            printf("%c", framebuffer[y][x]);
        }
        printf("\n");
    }
    printf("You are at room #%d\n", game_state->room);
    printf("The flag is at room #%d\n", FLAG_ROOM);
    if(MAZE[game_state->room].action_func) {
        printf("This room has a button.\n");
    }
    if(game_state->locked) {
        printf("That door is locked.\n");
    }
}

int main() {
    game_state_t game_state = {
        .room = START_ROOM,
        .curr_pos = 0,
        .locked = 0
    };
    int next_room, curr_pos;
    while(1) {
        render(&game_state);
        game_state.locked = 0;
        char inp = getchar();
        getchar();
        switch(inp) {
            case 'a': {
                next_room = MAZE[game_state.room].left_room;
                curr_pos = 2;
                break;
            }
            case 's': {
                next_room = MAZE[game_state.room].down_room;
                curr_pos = 1;
                break;
            }
            case 'd': {
                next_room = MAZE[game_state.room].right_room;
                curr_pos = 0;
                break;
            }
            case 'w': {
                next_room = MAZE[game_state.room].up_room;
                curr_pos = 3;
                break;
            }
            case 'p': {
                if(MAZE[game_state.room].action_func) {
                    MAZE[game_state.room].action_func();
                }
                break;
            }
            case 'q': {
                exit(0);
            }
            default:
                break;
        }
        switch(inp) {
            case 'a':
            case 's':
            case 'w':
            case 'd': {
                if(next_room & LOCKED_BIT) {
                    game_state.locked = 1;
                } else {
                    game_state.room = next_room;
                    game_state.curr_pos = curr_pos;
                }
                break;
            }
            default:
                break;
        }
    }
}
