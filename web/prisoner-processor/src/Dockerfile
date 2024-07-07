FROM oven/bun:1.1.16 as base
WORKDIR /app

FROM base AS install
RUN mkdir -p /tmp/install
COPY app/package.json /tmp/install
RUN cd /tmp/install && bun install

FROM base AS flagbuild
RUN apt update && apt install -y gcc
COPY flag.c /tmp/flag.c
RUN gcc -o /tmp/getflag /tmp/flag.c

FROM base AS release
RUN useradd -m -u 6969 ghostccamm
COPY --from=flagbuild /tmp/getflag /bin/getflag
COPY flag.txt /home/ghostccamm/flag.txt
RUN chown ghostccamm:ghostccamm /bin/getflag && \
        chown ghostccamm:ghostccamm /home/ghostccamm/flag.txt && \
        chmod 400 /home/ghostccamm/flag.txt && \
        chmod u+s /bin/getflag
COPY app/ .
COPY scripts/start.sh /home/bun/start.sh
RUN mkdir -p /app-data/yamls && \
        chown -R bun:bun /app && \
        chown bun:bun /app-data/yamls && \
        chmod +x /home/bun/start.sh && \
        mkdir -p /home/bun/backup && \
        cp -r /app /home/bun/backup/app
COPY --from=install /tmp/install/node_modules .
USER bun
EXPOSE 1337/tcp
ENTRYPOINT [ "/home/bun/start.sh" ]