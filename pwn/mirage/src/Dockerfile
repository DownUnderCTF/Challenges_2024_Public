FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    socat \
    python3 \
    python3-pip \
    xinetd \
    dbus-x11 \
    x11-xserver-utils \
    wget \
    gnupg \
    apt-transport-https \
    ca-certificates \
    curl \
    unzip \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxss1 \
    xdg-utils \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

ENV DISPLAY=:99
RUN python3 -m pip install selenium

RUN useradd -m ctf
RUN mkdir /home/ctf/chal

COPY chromium.zip /home/ctf/chal/chromium.zip
RUN unzip /home/ctf/chal/chromium.zip -d /home/ctf/chal/
COPY run.py /home/ctf/chal/pwn
COPY flag.txt /home/ctf/chal/flag.txt
RUN chmod +x /home/ctf/chal/pwn

EXPOSE 1337
USER ctf
ENTRYPOINT socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"timeout 30 /home/ctf/chal/pwn"