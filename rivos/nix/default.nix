# SPDX-FileCopyrightText: Copyright (c) 2022-2023 by Rivos Inc.
# SPDX-FileCopyrightText: Copyright (c) 2003-2022 Eelco Dolstra and the Nixpkgs/NixOS contributors
# SPDX-License-Identifier: MIT
# Rivos changes:
# Added src and version arguments.
# Removed darwin-specific optionals.
# Default audio/video/graphics support to false.
# Add plugins to a separate output.
# Remove big-parallel feature requirement.
# Set hostCpuTargets to minimize build times.
{
  lib,
  stdenv,
  fetchpatch,
  python3,
  python3Packages,
  zlib,
  pkg-config,
  glib,
  buildPackages,
  perl,
  pixman,
  vde2,
  alsa-lib,
  texinfo,
  flex,
  bison,
  lzo,
  snappy,
  libaio,
  libtasn1,
  gnutls,
  nettle,
  curl,
  ninja,
  meson,
  makeWrapper,
  removeReferencesTo,
  attr,
  libcap,
  libcap_ng,
  socat,
  lua5_3,
  guestAgentSupport ? with stdenv.hostPlatform; isLinux || isSunOS || isWindows,
  numaSupport ? stdenv.isLinux && !stdenv.isAarch32,
  numactl,
  seccompSupport ? stdenv.isLinux,
  libseccomp,
  alsaSupport ? false,
  pulseSupport ? false,
  libpulseaudio,
  sdlSupport ? false,
  SDL2,
  SDL2_image,
  jackSupport ? false,
  libjack2,
  gtkSupport ? false,
  gtk3,
  gettext,
  vte,
  wrapGAppsHook,
  vncSupport ? false,
  libjpeg,
  libpng,
  smartcardSupport ? false,
  libcacard,
  spiceSupport ? false,
  spice,
  spice-protocol,
  ncursesSupport ? !nixosTestRunner,
  ncurses,
  usbredirSupport ? spiceSupport,
  usbredir,
  xenSupport ? false,
  xen,
  cephSupport ? false,
  ceph,
  glusterfsSupport ? false,
  glusterfs,
  libuuid,
  openGLSupport ? sdlSupport,
  mesa,
  libepoxy,
  libdrm,
  virglSupport ? openGLSupport,
  virglrenderer,
  libiscsiSupport ? true,
  libiscsi,
  smbdSupport ? false,
  samba,
  tpmSupport ? true,
  uringSupport ? stdenv.isLinux,
  liburing,
  enableDocs ? false,
  hostCpuOnly ? false,
  hostCpuTargets ? (
    if hostCpuOnly
    then
      (lib.optional stdenv.isx86_64 "i386-softmmu"
        ++ ["${stdenv.hostPlatform.qemuArch}-softmmu"])
    else [
      "aarch64-softmmu"
      "riscv32-softmmu"
      "riscv64-softmmu"
      "x86_64-softmmu"
      "riscv64-linux-user"
    ]
  ),
  nixosTestRunner ? false,
  doCheck ? false,
  qemu, # for passthru.tests
  src,
  version,
}:
stdenv.mkDerivation rec {
  pname =
    "qemu"
    + lib.optionalString xenSupport "-xen"
    + lib.optionalString hostCpuOnly "-host-cpu-only"
    + lib.optionalString nixosTestRunner "-for-vm-tests";

  inherit src version;

  depsBuildBuild = [buildPackages.stdenv.cc];

  nativeBuildInputs =
    [makeWrapper removeReferencesTo pkg-config flex bison meson ninja perl python3 python3Packages.sphinx python3Packages.sphinx_rtd_theme]
    ++ lib.optionals gtkSupport [wrapGAppsHook];

  buildInputs =
    [
      zlib
      glib
      perl
      pixman
      vde2
      texinfo
      lzo
      snappy
      libtasn1
      gnutls
      nettle
      curl
      lua5_3
    ]
    ++ lib.optionals ncursesSupport [ncurses]
    ++ lib.optionals seccompSupport [libseccomp]
    ++ lib.optionals numaSupport [numactl]
    ++ lib.optionals alsaSupport [alsa-lib]
    ++ lib.optionals pulseSupport [libpulseaudio]
    ++ lib.optionals sdlSupport [SDL2 SDL2_image]
    ++ lib.optionals jackSupport [libjack2]
    ++ lib.optionals gtkSupport [gtk3 gettext vte]
    ++ lib.optionals vncSupport [libjpeg libpng]
    ++ lib.optionals smartcardSupport [libcacard]
    ++ lib.optionals spiceSupport [spice-protocol spice]
    ++ lib.optionals usbredirSupport [usbredir]
    ++ lib.optionals stdenv.isLinux [libaio libcap_ng libcap attr]
    ++ lib.optionals xenSupport [xen]
    ++ lib.optionals cephSupport [ceph]
    ++ lib.optionals glusterfsSupport [glusterfs libuuid]
    ++ lib.optionals openGLSupport [mesa libepoxy libdrm]
    ++ lib.optionals virglSupport [virglrenderer]
    ++ lib.optionals libiscsiSupport [libiscsi]
    ++ lib.optionals smbdSupport [samba]
    ++ lib.optionals uringSupport [liburing];

  dontUseMesonConfigure = true; # meson's configurePhase isn't compatible with qemu build

  outputs = ["out" "plugins"] ++ lib.optional guestAgentSupport "ga";
  # On aarch64-linux we would shoot over the Hydra's 2G output limit.
  separateDebugInfo = !(stdenv.isAarch64 && stdenv.isLinux);

  patches =
    [
      ./fix-qemu-ga.patch

      # Workaround for upstream issue with nested virtualisation: https://gitlab.com/qemu-project/qemu/-/issues/1008
      (fetchpatch {
        url = "https://gitlab.com/qemu-project/qemu/-/commit/3e4546d5bd38a1e98d4bd2de48631abf0398a3a2.diff";
        sha256 = "sha256-oC+bRjEHixv1QEFO9XAm4HHOwoiT+NkhknKGPydnZ5E=";
        revert = true;
      })
    ]
    ++ lib.optional nixosTestRunner ./force-uid0-on-9p.patch;

  postPatch = ''
    # Otherwise tries to ensure /var/run exists.
    sed -i "/install_emptydir(get_option('localstatedir') \/ 'run')/d" \
        qga/meson.build

    # glibc 2.33 compat fix: if `has_statx = true` is set, `tools/virtiofsd/passthrough_ll.c` will
    # rely on `stx_mnt_id`[1] which is not part of glibc's `statx`-struct definition.
    #
    # `has_statx` will be set to `true` if a simple C program which uses a few `statx`
    # consts & struct fields successfully compiles. It seems as this only builds on glibc-2.33
    # since most likely[2] and because of that, the problematic code-path will be used.
    #
    # [1] https://github.com/torvalds/linux/commit/fa2fcf4f1df1559a0a4ee0f46915b496cc2ebf60#diff-64bab5a0a3fcb55e1a6ad77b1dfab89d2c9c71a770a07ecf44e6b82aae76a03a
    # [2] https://sourceware.org/git/?p=glibc.git;a=blobdiff;f=io/bits/statx-generic.h;h=c34697e3c1fd79cddd60db294302e461ed8db6e2;hp=7a09e94be2abb92d2df612090c132e686a24d764;hb=88a2cf6c4bab6e94a65e9c0db8813709372e9180;hpb=c4e4b2e149705559d28b16a9b47ba2f6142d6a6c
    substituteInPlace meson.build \
      --replace 'has_statx = cc.links(statx_test)' 'has_statx = false'
  '';

  preConfigure = ''
    unset CPP # intereferes with dependency calculation
    # this script isn't marked as executable b/c it's indirectly used by meson. Needed to patch its shebang
    chmod +x ./scripts/shaderinclude.py
    patchShebangs .
    # avoid conflicts with libc++ include for <version>
    mv VERSION QEMU_VERSION
    substituteInPlace configure \
      --replace '$source_path/VERSION' '$source_path/QEMU_VERSION'
    substituteInPlace meson.build \
      --replace "'VERSION'" "'QEMU_VERSION'"
  '';

  configureFlags =
    [
      "--disable-strip" # We'll strip ourselves after separating debug info.
      (lib.enableFeature enableDocs "docs")
      "--enable-tools"
      "--enable-plugins"
      "--localstatedir=/var"
      "--sysconfdir=/etc"
      # Always use our Meson, not the bundled version, which doesn't
      # have our patches and will be subtly broken because of that.
      "--meson=meson"
      "--cross-prefix=${stdenv.cc.targetPrefix}"
      "--cpu=${stdenv.hostPlatform.uname.processor}"
      (lib.enableFeature guestAgentSupport "guest-agent")
    ]
    ++ lib.optional numaSupport "--enable-numa"
    ++ lib.optional seccompSupport "--enable-seccomp"
    ++ lib.optional smartcardSupport "--enable-smartcard"
    ++ lib.optional spiceSupport "--enable-spice"
    ++ lib.optional usbredirSupport "--enable-usb-redir"
    ++ lib.optional (hostCpuTargets != null) "--target-list=${lib.concatStringsSep "," hostCpuTargets}"
    ++ lib.optional stdenv.isLinux "--enable-linux-aio"
    ++ lib.optional gtkSupport "--enable-gtk"
    ++ lib.optional xenSupport "--enable-xen"
    ++ lib.optional cephSupport "--enable-rbd"
    ++ lib.optional glusterfsSupport "--enable-glusterfs"
    ++ lib.optional openGLSupport "--enable-opengl"
    ++ lib.optional virglSupport "--enable-virglrenderer"
    ++ lib.optional tpmSupport "--enable-tpm"
    ++ lib.optional libiscsiSupport "--enable-libiscsi"
    ++ lib.optional smbdSupport "--smbd=${samba}/bin/smbd"
    ++ lib.optional uringSupport "--enable-linux-io-uring";

  dontWrapGApps = true;

  postFixup =
    ''
      # the .desktop is both invalid and pointless
      rm -f $out/share/applications/qemu.desktop
    ''
    + lib.optionalString guestAgentSupport ''
      # move qemu-ga (guest agent) to separate output
      mkdir -p $ga/bin
      mv $out/bin/qemu-ga $ga/bin/
      ln -s $ga/bin/qemu-ga $out/bin
      remove-references-to -t $out $ga/bin/qemu-ga
    ''
    + lib.optionalString gtkSupport ''
      # wrap GTK Binaries
      for f in $out/bin/qemu-system-*; do
        wrapGApp $f
      done
    '';
  preBuild = "cd build";

  postBuild = ''
    pushd contrib/plugins
    make -j$NIX_BUILD_CORES
    popd
  '';

  # tests can still timeout on slower systems
  inherit doCheck;
  checkInputs = [socat];
  preCheck = ''
    # time limits are a little meagre for a build machine that's
    # potentially under load.
    substituteInPlace ../tests/unit/meson.build \
      --replace 'timeout: slow_tests' 'timeout: 50 * slow_tests'
    substituteInPlace ../tests/qtest/meson.build \
      --replace 'timeout: slow_qtests' 'timeout: 50 * slow_qtests'
    substituteInPlace ../tests/fp/meson.build \
      --replace 'timeout: 90)' 'timeout: 300)'

    # point tests towards correct binaries
    substituteInPlace ../tests/unit/test-qga.c \
      --replace '/bin/echo' "$(type -P echo)"
    substituteInPlace ../tests/unit/test-io-channel-command.c \
      --replace '/bin/socat' "$(type -P socat)"

    # combined with a long package name, some temp socket paths
    # can end up exceeding max socket name len
    substituteInPlace ../tests/qtest/bios-tables-test.c \
      --replace 'qemu-test_acpi_%s_tcg_%s' '%s_%s'

    # get-fsinfo attempts to access block devices, disallowed by sandbox
    sed -i -e '/\/qga\/get-fsinfo/d' -e '/\/qga\/blacklist/d' \
      ../tests/unit/test-qga.c
  '';

  # Add a ‘qemu-kvm’ wrapper for compatibility/convenience.
  postInstall = ''
    ln -s $out/libexec/virtiofsd $out/bin
    ln -s $out/bin/qemu-system-${stdenv.hostPlatform.qemuArch} $out/bin/qemu-kvm

    # Add the plugins to their own output.
    mkdir -p $plugins/lib
    cp contrib/plugins/*.so $plugins/lib/
  '';

  passthru = {
    qemu-system-i386 = "bin/qemu-system-i386";
    tests = {
      qemu-tests = qemu.override {doCheck = true;};
    };
  };

  meta = with lib; {
    homepage = "http://www.qemu.org/";
    description = "A generic and open source machine emulator and virtualizer";
    license = licenses.gpl2Plus;
    mainProgram = "qemu-kvm";
    maintainers = with maintainers; [eelco qyliss];
    platforms = platforms.unix;
    priority = 10; # Prefer virtiofsd from the virtiofsd package.
  };
}
