//
//  ViewController.m
//  chal
//
//  Created by u on 15/6/2024.
//

#import "ViewController.h"
#import <Foundation/Foundation.h>

typedef struct {
    float h;
    float s;
    float v;
} hsv_t;
typedef unsigned char level_t[5];
typedef struct {
    int currentLevelNumber;
    int currentLevelPressed;
    int ded;
} game_state_t;
level_t LEVELS[74] = {
    {2, 4, 1, 0, 3},
    {3, 2, 0, 4, 1},
    {2, 4, 0, 3, 1},
    {3, 2, 0, 1, 4},
    {2, 4, 3, 0, 1},
    {0, 1, 3, 4, 2},
    {0, 1, 2, 4, 3},
    {2, 0, 1, 3, 4},
    {4, 3, 1, 2, 0},
    {3, 4, 2, 1, 0},
    {4, 0, 1, 3, 2},
    {4, 3, 0, 1, 2},
    {2, 0, 3, 4, 1},
    {3, 4, 2, 1, 0},
    {4, 1, 0, 3, 2},
    {2, 0, 1, 3, 4},
    {2, 0, 1, 3, 4},
    {4, 0, 3, 1, 2},
    {3, 4, 2, 1, 0},
    {4, 0, 1, 3, 2},
    {4, 3, 1, 0, 2},
    {3, 4, 2, 1, 0},
    {4, 2, 3, 0, 1},
    {4, 3, 0, 1, 2},
    {2, 0, 3, 4, 1},
    {4, 3, 0, 2, 1},
    {4, 3, 0, 2, 1},
    {4, 1, 2, 3, 0},
    {4, 2, 1, 0, 3},
    {4, 1, 0, 3, 2},
    {3, 4, 2, 1, 0},
    {4, 0, 2, 1, 3},
    {4, 3, 1, 2, 0},
    {4, 3, 1, 0, 2},
    {4, 3, 1, 0, 2},
    {2, 0, 1, 3, 4},
    {4, 2, 1, 0, 3},
    {4, 3, 0, 2, 1},
    {3, 4, 2, 1, 0},
    {0, 1, 3, 2, 4},
    {2, 1, 3, 0, 4},
    {0, 1, 2, 4, 3},
    {2, 0, 3, 1, 4},
    {4, 1, 2, 0, 3},
    {0, 1, 3, 2, 4},
    {4, 1, 3, 0, 2},
    {4, 0, 2, 1, 3},
    {0, 1, 2, 3, 4},
    {2, 0, 1, 3, 4},
    {0, 1, 2, 4, 3},
    {2, 1, 0, 4, 3},
    {0, 1, 2, 3, 4},
    {0, 1, 2, 4, 3},
    {2, 0, 1, 4, 3},
    {2, 1, 3, 4, 0},
    {4, 0, 1, 3, 2},
    {4, 2, 0, 1, 3},
    {4, 0, 3, 2, 1},
    {4, 3, 2, 1, 0},
    {4, 2, 3, 0, 1},
    {2, 1, 3, 0, 4},
    {0, 1, 3, 2, 4},
    {2, 1, 3, 4, 0},
    {0, 1, 2, 3, 4},
    {2, 0, 1, 3, 4},
    {2, 0, 1, 4, 3},
    {4, 2, 3, 0, 1},
    {4, 3, 2, 0, 1},
    {0, 1, 3, 2, 4},
    {4, 2, 3, 1, 0},
    {2, 1, 3, 4, 0},
    {0, 1, 2, 3, 4},
    {0, 1, 2, 4, 3},
    {0, 1, 4, 3, 2}
};
hsv_t COLOURS[5] = {
    { .h = 0.6944, .s = 0.5, .v = 0.65 },
    { .h = 0.8139, .s = 0.5, .v = 0.65 },
    { .h = 0.5500, .s = 0.5, .v = 0.65 },
    { .h = 0.3345, .s = 0.5, .v = 0.65 },
    { .h = 0.0001, .s = 0.5, .v = 0.65 },
};

void setCircleButtonColour(IBOutlet UIButton* button, UIColor* col) {
    button.layer.cornerRadius = button.frame.size.height / 2.0;
    //button.layer.masksToBounds = true;
    button.backgroundColor = col;
}

char ptoc(level_t level) {
    NSMutableArray* permutation = [NSMutableArray arrayWithCapacity:5];
    for(int j = 0; j < 5; j++) {
        NSNumber *n = @(level[j]);
        [permutation addObject:n];
    }
    NSInteger n = [permutation count];
    NSUInteger bits = 0;
    BOOL unused[n];
    memset(unused, YES, n);
    for (NSInteger i = 0; i < n - 1; ++i) {
        NSInteger count = 0;
        NSInteger current = [permutation[i] integerValue];
        for (NSInteger j = 0; j < n; ++j) {
            if (unused[j] && j < current) {
                ++count;
            }
        }
        bits += count * tgamma(n - i);
        unused[current] = NO;
    }
    if(bits < 10) {
        bits += 120;
    }
    return (char)bits;
}

UIColor* hsvToUIColor(hsv_t hsv, int desat) {
    float desatMultiplier = desat < 5 ? 1 : pow(0.6, desat - 4);
    return [UIColor colorWithHue:hsv.h saturation:hsv.s*desatMultiplier brightness:hsv.v alpha:1.0];
}

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UIButton *B1;
@property (weak, nonatomic) IBOutlet UIButton *B2;
@property (weak, nonatomic) IBOutlet UIButton *B3;
@property (weak, nonatomic) IBOutlet UIButton *B4;
@property (weak, nonatomic) IBOutlet UIButton *B5;
@property (weak, nonatomic) IBOutlet UIButton *S1;
@property (weak, nonatomic) IBOutlet UIButton *S2;
@property (weak, nonatomic) IBOutlet UIButton *S3;
@property (weak, nonatomic) IBOutlet UIButton *S4;
@property (weak, nonatomic) IBOutlet UIButton *S5;
@property (weak, nonatomic) IBOutlet UILabel *FL;
@property (nonatomic) game_state_t *game;

- (void)doPress:(int)button;
- (void)renderState;
- (void)restart;

@end

@implementation ViewController

- (IBAction)B1:(id)sender {
    [self doPress:(int)0];
}
- (IBAction)B2:(id)sender {
    [self doPress:(int)1];
}
- (IBAction)B3:(id)sender {
    [self doPress:(int)2];
}
- (IBAction)B4:(id)sender {
    [self doPress:(int)3];
}
- (IBAction)B5:(id)sender {
    [self doPress:(int)4];
}
- (IBAction)restartButton:(id)sender {
    [self restart];
}

- (void)restart {
    self.game->currentLevelNumber = 0;
    self.game->ded = 0;
    self.game->currentLevelPressed = 0;
    self.FL.text = @"Flag: ";
    [self renderState];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.game = (game_state_t*)malloc(sizeof(game_state_t));
    self.game->currentLevelNumber = 0;
    self.game->currentLevelPressed = 0;
    self.FL.text = @"Flag: ";
    
    [self renderState];
    
}

- (void)renderState {
    NSArray* S = @[ self.S1, self.S2, self.S3, self.S4, self.S5 ];
    NSArray* B = @[ self.B1, self.B2, self.B3, self.B4, self.B5 ];
    for(int i = 0; i < 5; i++) {
        setCircleButtonColour(S[i], hsvToUIColor(COLOURS[LEVELS[self.game->currentLevelNumber][i]], self.game->currentLevelNumber));
        setCircleButtonColour(B[i], hsvToUIColor(COLOURS[i], self.game->currentLevelNumber));
    }
}

- (void)doPress:(int)button {
    NSLog(@"button %d pressed", button);
    
    if(self.game->ded) {
        return;
    }
    
    if(LEVELS[self.game->currentLevelNumber][self.game->currentLevelPressed] != button) {
        self.game->ded = 1;
        self.FL.text = @"You lose...";
        return;
    }
    
    if(self.game->currentLevelPressed == 4) {
        char c = ptoc(LEVELS[self.game->currentLevelNumber]);
        self.game->currentLevelNumber++;
        self.game->currentLevelPressed = 0;
        self.FL.text = [self.FL.text stringByAppendingFormat:@"%c", c];
        if(self.game->currentLevelNumber == 74) {
            self.game->ded = 1;
            self.FL.text = [self.FL.text stringByAppendingString:@"\nYou win!"];
            return;
        }
        [self renderState];
        return;
    }
    
    self.game->currentLevelPressed++;
}

@end
