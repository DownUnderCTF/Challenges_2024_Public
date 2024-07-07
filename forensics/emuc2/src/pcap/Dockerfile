FROM ubuntu:22.04

RUN mkdir /output

RUN apt-get update

RUN apt-get install -y wget tcpdump curl

RUN wget https://dist.ipfs.tech/kubo/v0.29.0/kubo_v0.29.0_linux-amd64.tar.gz

RUN tar -xvzf kubo_v0.29.0_linux-amd64.tar.gz

RUN /kubo/install.sh

COPY noise.sh /noise.sh

RUN chmod +x /noise.sh

ENTRYPOINT ["/noise.sh"]