FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y gcc-aarch64-linux-gnu qemu-user qemu-user-static --fix-missing \
    && rm -r /var/lib/apt/lists/*

ENV JAIL_CWD=/chal

COPY ./flag.txt /home/ctf/chal
COPY ./ld-linux-aarch64.so.1 /home/ctf/chal
COPY ./libc.so.6 /home/ctf/chal
COPY ./pacsh /home/ctf/chal
COPY ./run.sh /home/ctf/chal/pwn
