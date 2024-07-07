FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y libaio-dev libasan6 libasound2-dev libattr1-dev libbpf-dev libbrlapi-dev libbz2-dev libc6-dev libcacard-dev libcap-ng-dev libcapstone-dev libcmocka-dev libcurl4-gnutls-dev libdaxctl-dev libdrm-dev libepoxy-dev libfdt-dev libffi-dev libfuse3-dev libgbm-dev libgcrypt20-dev libglib2.0-dev libglusterfs-dev libgnutls28-dev libgtk-3-dev libibumad-dev libibverbs-dev libiscsi-dev libjemalloc-dev libjpeg-turbo8-dev libjson-c-dev liblttng-ust-dev liblzo2-dev libncursesw5-dev libnfs-dev libnuma-dev libpam0g-dev libpcre2-dev libpipewire-0.3-dev libpixman-1-dev libpmem-dev libpng-dev libpulse-dev librbd-dev librdmacm-dev libsasl2-dev libsdl2-dev libsdl2-image-dev libseccomp-dev libselinux1-dev libslirp-dev libsnappy-dev libsndio-dev libspice-protocol-dev libspice-server-dev libssh-dev libsystemd-dev libtasn1-6-dev libubsan1 libudev-dev liburing-dev libusb-1.0-0-dev libusbredirhost-dev libvdeplug-dev libvirglrenderer-dev libvte-2.91-dev libxen-dev libzstd-dev llvm locales make meson mtools multipath-tools ncat nettle-dev socat python3 --fix-missing \
    && rm -r /var/lib/apt/lists/*

RUN mkdir /home/ctf
WORKDIR /home/ctf

COPY ./qemu-system-xtensa /home/ctf
COPY ./flash-base.bin /home/ctf
COPY ./qemu-efuse.bin /home/ctf
COPY ./esp32-v3-rom.bin /home/ctf
COPY ./esp32-v3-rom-app.bin /home/ctf
COPY ./run.py /home/ctf

ENTRYPOINT socat -dd TCP4-LISTEN:1337,fork,reuseaddr EXEC:"timeout 30 ./run.py"
