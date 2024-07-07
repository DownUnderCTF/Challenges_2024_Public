import random
import math

w = list(b'DUCTF{2tsp_Vegemite}')
a = 27
d = 21

INGREDIENTS = [
    ('kg', 'bread crumbs'),
    ('ml', 'hot canola oil'),
    ('kg', 'egg yolks'),
    ('teaspoons', 'all purpose spices'),
    ('teaspoons', 'herbs'),
    ('kg', 'flour'),
    ('kg', 'sliced chicken breasts'),
    ('dashes', 'salt'),
    ('dashes', 'pepper'),
    ('dashes', 'pride and joy'),
    ('kg', 'tomato sauce'),
    ('g', 'cheese'),
    ('kg', 'ham'),
    ('g', 'pasta sauce'),
    ('dashes', 'chilli flakes'),
    ('kg', 'onion'),
    ('dashes', 'basil'),
    ('dashes', 'oregano'),
    ('dashes', 'parsley'),
    ('teaspoons', 'sugar'),
    ('kg', 'garlic'),
]

TEMPLATE = '''Chicken Parmi.

Our Cyber Chef has been creating some wacky recipes recently, though he has been rather protective of his secret ingredients.
Use this Chicken Parmi recipe and decipher the missing values to discover the chef's secret ingredient!
This recipe produces the flag in flag format.

Ingredients.
{a} dashes pain
{d} cups effort
1 cup water
{ingredients}

Cooking time: 25 minutes.

Pre-heat oven to 180 degrees Celsius.

Method.
{method}
Liquefy contents of the mixing bowl.
Pour contents of the mixing bowl into the 1st baking dish.
Refrigerate for 1 hour.
'''

ingredients = ''
method = ''

values = []

for c in w[::-1]:
    c -= d
    b = random.getrandbits(1)
    if b == 0:
        q = c // a
    else:
        q = math.ceil(c / a)
    r = c - a * q
    ig = INGREDIENTS.pop(0)
    ingredients += f'{abs(r)} {ig[0]} {ig[1]}\n'
    if q:
        method += f'Put water into 1st mixing bowl.\n'
    for _ in range(q - 1):
        method += f'Add water to 1st mixing bowl.\n'
    method += f'Combine pain into 1st mixing bowl.\n'
    if r > 0:
        method += f'Add {ig[1]} to 1st mixing bowl.\n'
    elif r < 0:
        method += f'Remove {ig[1]} from 1st mixing bowl.\n'
    method += f'Add effort to 1st mixing bowl.\n'
    assert a * q + r == c
    values.append((q, r))

# sanity check to make sure 2tsp_Vegemite is the only valid answer
answer_exists = False
for a_ in range(256):
    for d_ in range(256):
        out = []
        for q, r in values:
            out.append(a_ * q + r + d_)
        # if all(0x20 <= c <= 0x7f for c in out):
        #     f = ''.join(map(chr, out))
        #     if f[::-1].startswith('DUCTF{'):
        #         print(f[::-1])
        if out[::-1] == w:
            answer_exists = True
assert answer_exists 

print(TEMPLATE.format(a=a, d=d, ingredients=ingredients[:-1], method=method[:-1]))
