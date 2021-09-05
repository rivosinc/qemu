# Copyright 2021 RiVos, Inc.
FROM ubuntu:20.04 as qemu_builder

# Don't let debs run any interactive configuration scripts.
ENV DEBIAN_FRONTEND=noninteractive

# Install build deps for qemu.
RUN apt-get update && \
    apt-get -y -qq install build-essential \
                           git \
                           libaio-dev \
                           libbz2-dev \
                           libcap-dev \
                           libcap-ng-dev \
                           libcurl4-gnutls-dev \
                           libglib2.0-dev \
                           libfdt-dev \
                           liblzo2-dev \
                           libpixman-1-dev \
                           libssh2-1-dev \
                           ninja-build \
                           zlib1g-dev

COPY . /src

WORKDIR /tmp/build
RUN /src/configure --prefix=/rivos/qemu \
                   --target-list=riscv32-softmmu,riscv64-softmmu,riscv32-linux-user,riscv64-linux-user,x86_64-linux-user \
                   --enable-plugins && \
    make -j && \
    make plugins && \
    make install

# Copy the built qemu into a fresh image.
FROM ubuntu:20.04 as qemu
COPY --from=qemu_builder /rivos/qemu /rivos/qemu
COPY --from=qemu_builder /tmp/build/contrib/plugins/*.so /rivos/qemu/plugins/
ENV PATH "${PATH}:/rivos/qemu/bin"

RUN apt-get update && \
    apt-get -y -qq install libaio1 \
                           libbz2-1.0 \
                           libcap2 \
                           libcap-ng0 \
                           libcurl4 \
                           libglib2.0-0 \
                           libfdt1 \
                           liblzo2-2 \
                           libpixman-1-0 \
                           libssh2-1 \
                           zlib1g && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists
