maxVal = 50

sample = "FTCUD"

ingredients = '''5 kg onion
9 dashes basil
19 dashes oregano
10 dashes parsley
20 teaspoons sugar'''
ingredients = ingredients.split('\n')

method = '''Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Remove onion from 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add basil to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add oregano to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Add water to 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add parsley to 1st mixing bowl.
Add effort to 1st mixing bowl.
Put water into 1st mixing bowl.
Combine pain into 1st mixing bowl.
Add sugar to 1st mixing bowl.
Add effort to 1st mixing bowl.'''

method = method.split('\n')
sampleNum = -1
sampleDec = 0
found = []
for line in method:
    if "Put water" in line:
        sampleNum += 1
        water = 1
        sampleDec = ord(sample[sampleNum])
        print(sample[sampleNum])
    if "Add water" in line:
        water += 1
    if "Add " in line and "Add water" not in line and "Add effort" not in line:
        mathType = "Add"
        ingredient = line.split(" ")[1]
        for ingredientLine in ingredients:
            if ingredient in ingredientLine:
                ammount = int(ingredientLine.split(' ')[0])
    if "Remove " in line:
        mathType = "Remove"
        ingredient = line.split(" ")[1]
        for ingredientLine in ingredients:
            if ingredient in ingredientLine:
                ammount = int(ingredientLine.split(' ')[0])
    if "Add effort" in line:
        if sampleNum == 0:
            y = 0
            while y < maxVal:
                x = 0
                while x < maxVal:
                    if mathType == "Add":
                        value = (((water*x)+ammount)+y)
                    elif mathType == "Remove":
                        value = (((water*x)-ammount)+y)
                    if value == sampleDec:
                        print(f'Solved: x={x},y={y}')
                        found.append({'x':x,'y':y})
                    x += 1
                y += 1
        else:
            for finding in found:
                if mathType == "Add":
                    value = (((water*finding['x'])+ammount)+finding['y'])
                elif mathType == "Remove":
                    value = (((water*finding['x'])-ammount)+finding['y'])
                if value == sampleDec:
                    print(f'Solved: x={finding["x"]},y={finding["y"]}')