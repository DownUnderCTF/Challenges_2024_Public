FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal

COPY ./ld-linux-x86-64.so.2 /home/ctf/chal
COPY ./libc.so.6 /home/ctf/chal
COPY ./yawa /home/ctf/chal/pwn
COPY ./flag.txt /home/ctf/chal
