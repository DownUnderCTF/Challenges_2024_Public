FROM ghcr.io/downunderctf/docker-vendor/nsjail:ubuntu-22.04

RUN pip install -t /lib/python3/dist-packages pycryptodome

ENV TIME_LIMIT=300
ENV FLAG=DUCTF{should_have_used_authenticated_encryption!}

COPY ./decrypt-then-eval.py /home/ctf/chal/pwn
