FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV JAIL_CWD=/chal
ENV TIME_LIMIT=600
ENV CPU_SHARE_MS=300

COPY ./flag.txt /home/ctf/chal
COPY ./ld-linux-x86-64.so.2 /home/ctf/chal
COPY ./libc.so.6 /home/ctf/chal
COPY ./sheep /home/ctf/chal/pwn
