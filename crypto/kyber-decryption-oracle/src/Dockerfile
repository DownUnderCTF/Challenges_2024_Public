FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV TIME_LIMIT=100
ENV JAIL_CWD=/chal
ENV FLAG="DUCTF{decryption_oracle_is_too_powerful!!}"

COPY ./libpqcrystals_kyber512_ref.so /home/ctf/chal
COPY ./kyber-decryption-oracle.py /home/ctf/chal/pwn
