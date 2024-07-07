FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y gcc-aarch64-linux-gnu qemu-user qemu-user-static --fix-missing \
    && rm -r /var/lib/apt/lists/*

ENV JAIL_CWD=/chal

COPY ./flag.txt /home/ctf/chal
COPY ./number-mashing /home/ctf/chal
COPY ./run.sh /home/ctf/chal/pwn
