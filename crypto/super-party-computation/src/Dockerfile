FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

ENV TIME_LIMIT=600
ENV FLAG=DUCTF{d0nt_w0rry_th3_3mus_w1ll_b3_0kay}

COPY ./server.py /home/ctf/chal/pwn
RUN chmod +x /home/ctf/chal/pwn
