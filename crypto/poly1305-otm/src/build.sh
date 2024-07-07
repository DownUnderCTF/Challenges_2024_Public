#!/bin/sh

build_script=$(mktemp)
echo '#!/bin/bash' >> $build_script
echo "cd /tmp/build" >> $build_script
echo "apt update -y" >> $build_script
echo "apt install -y clang libmbedtls-dev patchelf" >> $build_script
echo "cp /lib/x86_64-linux-gnu/libmbedcrypto.a ." >> $build_script
echo "clang -o chall chall.c -Wno-everything -L./ -lmbedcrypto -fno-stack-protector -O0 -pie" >> $build_script
echo "cp /lib/x86_64-linux-gnu/libc.so.6 /lib64/ld-linux-x86-64.so.2 ." >> $build_script
echo "patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./chall" >> $build_script
chmod +x $build_script

docker run -v$(pwd):/tmp/build -v"$build_script:/tmp/build/build.sh" ubuntu:22.04@sha256:a6d2b38300ce017add71440577d5b0a90460d0e57fd7aec21dd0d1b0761bbfb2 "/tmp/build/build.sh"
