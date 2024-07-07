import sys

sys.set_int_max_str_digits(104116)

mapping = {
    "00": ">",
    "01": "<",
    "02": "+",
    "10": "-",
    "11": ".",
    "12": ",",
    "20": "[",
    "21": "]",
}


def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]


def main():
    data = open(sys.argv[1], "rb").read()

    d = int.from_bytes(data)

    raw_program = "".join([str(i) for i in numberToBase(d, 3)])

    if len(raw_program) % 2 != 0:
        raw_program = "0" + raw_program

    n = 2

    raw_program = [raw_program[i : i + n] for i in range(0, len(raw_program), n)]

    program = [mapping[i] for i in raw_program]

    print("".join(program))


if __name__ == "__main__":
    main()
