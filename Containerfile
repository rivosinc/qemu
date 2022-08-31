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
                           liblua5.3-dev \
                           liblzo2-dev \
                           libpixman-1-dev \
                           libssh2-1-dev \
                           ninja-build \
                           zlib1g-dev

COPY . /src

WORKDIR /tmp/build
RUN /src/configure --prefix=/rivos/qemu \
                   --target-list=riscv32-softmmu,riscv64-softmmu,aarch64-softmmu,riscv32-linux-user,riscv64-linux-user,x86_64-linux-user,aarch64-linux-user \
                   --enable-plugins && \
    make -j && \
    make plugins && \
    make install

### Stage 2: Create a .deb Ubuntu package
FROM gitlab.ba.rivosinc.com:5050/rv/it/int/rivos-sdk/packager:latest as qemu_packager

COPY --from=qemu_builder /rivos/qemu /rivos/qemu
COPY --from=qemu_builder /tmp/build/contrib/plugins/*.so /rivos/qemu/plugins/

ARG UPVER
ARG PKGVER
ARG CI_JOB_TOKEN
ARG CI_PROJECT_NAME
ARG CI_PROJECT_URL
ARG SECTION

RUN ./build_upload_package --deb \
  --arch amd64 \
  ${SECTION:+--component ${SECTION}} \
  --description "Open-source machine emulator." \
  --directory "/rivos/qemu" \
  -d libaio1 \
  -d libbz2-1.0 \
  -d libcap2 \
  -d libcap-ng0 \
  -d libcurl4 \
  -d libglib2.0-0 \
  -d libfdt1 \
  -d liblzo2-2 \
  -d libpixman-1-0 \
  -d libssh2-1 \
  -d zlib1g \
  --license "GPL-2.0" \
  --name "${CI_PROJECT_NAME}" \
  --pkg_version "${PKGVER}" \
  --token "${CI_JOB_TOKEN}" \
  --url "${CI_PROJECT_URL}" \
  --upstream_version "${UPVER}"

### Stage 3: Copy the built qemu into a fresh container image.
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
