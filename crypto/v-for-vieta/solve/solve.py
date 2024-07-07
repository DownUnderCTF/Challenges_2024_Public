#!/usr/bin/env python

import json
from pwn import *
import gmpy2

context.log_level = "debug"


def get_k(conn):
    try:
        k_json = json.loads(conn.recvline().decode())
        if "flag" in k_json:
            print(k_json["flag"])
            exit(0)
        return k_json["k"], k_json["level"]
    except json.decoder.JSONDecodeError:
        conn.recvall()


def test_hyperbola(a, b, k):
    num = a**2 + a * b + b**2
    denom = 2 * a * b + 1
    assert num % denom == 0
    assert num // denom == k


def solve():
    conn = connect("127.0.0.1", 1337)
    conn.recvline()
    while True:
        k, level = get_k(conn)

        a, b = gmpy2.isqrt(k), 0
        while a.bit_length() <= 2048 or b.bit_length() <= 2048:
            b = (2 * k - 1) * a - b
            test_hyperbola(a, b, k)
            a, b = b, a
            test_hyperbola(a, b, k)
            print(f"target = {level}\tb.bitlength() = {b.bit_length()}\ta.bit_length() = {a.bit_length()}")

        challenge = {"a": int(a), "b": int(b)}
        conn.sendline(json.dumps(challenge).encode())


if __name__ == "__main__":
    solve()
