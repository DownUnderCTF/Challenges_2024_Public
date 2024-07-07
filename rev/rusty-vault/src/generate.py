#!/usr/bin/env python3
import argparse
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_get_rust_slice(plaintext):
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return (','.join(map(str,aes_key)), 
        ','.join(map(str,nonce)), 
        ','.join(map(str,ciphertext)) + ',' + ','.join(map(str,tag)) )

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f',
                        '--flag',
                        type=argparse.FileType('r'),
                        required=True,
                        help='File containing the desired flag for the challenge.')
    parser.add_argument('-s',
                        '--src',
                        type=argparse.FileType('r'),
                        required=True,
                        help='Src template file.')
    parser.add_argument('-o',
                        '--out',
                        type=argparse.FileType('w+'),
                        required=True,
                        help='Resultant src file with the correct flag.')

    args = parser.parse_args()
    

    (key, nonce, result_str) = encrypt_get_rust_slice(args.flag.read().encode())
    rust_src = string.Template(args.src.read())
    out_src = rust_src.substitute({
        'RESULT': result_str,
        'KEY': key,
        'NONCE': nonce,
        })
    args.out.write(out_src)
    
