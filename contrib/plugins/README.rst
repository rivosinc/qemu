============================
Rivos QEMU Profiling Plugins
============================

This directory contains a set of qemu plugins which can be used for profiling an application running in qemu.  These plugins are built and included in the rivos-sdk by default.

Step 0
======

All of the instructions on this page assume you are already able to run the application to completion on qemu-riscv64.  It is strongly recommnded you double check this before moving on.

The rest of this assumes you are using qemu-riscv64 from the standard install location provieed by rivos-sdk, and that you have the following environment variables configured.

.. code-block:: console

  # Needed for architectural support
  export QEMU_CPU=rivos-sentinel
  # Needed for dynamically loaded programs to work.
  export QEMU_LD_PREFIX=/rivos/riscv-gnu-toolchain/sysroot/

Our example program will be coremark.

.. code-block:: console

  # This should finish in about 20 seconds or so.  The arguments
  # fix the number of iterations to allow easier cross comparison.
  /rivos/qemu/bin/qemu-riscv64 ./coremark.riscv 0 0 0 40000

You can download this binary from the `coremark CI repo <https://gitlab.ba.rivosinc.com/rv/sandbox/adlr/coremark/-/jobs/422081>`_.  This links to a specific build revision; you may wish to grab a newer build.
  
Collecting Dynamic Instruction Count
====================================

The bvvgen plugin collects (among many other details) the dynamic instruction count of the executed program.

.. code-block:: console

  /rivos/qemu/bin/qemu-riscv64 -plugin /rivos/qemu/plugins/libbbvgen.so,bbv=$PWD/bbvvs.gz,bbvi=$PWD/bbvi.gz ./coremark.riscv 0 0 0 40000

In the generated bbvi.gz file, you will find a single json file.  That file contains (towards the bottom) an entry with the key "instructions", and an integer value which should be in the 10s of billions for this test.  That's your dynamic instruction count.
  
A couple of potential gotchas here:

* Both options (bbv, and bbvi) are required despite the fact we only care about one.  The order of appearance in the command line also appears important.
* Make sure you include the ".gz" suffix.  At least on Ubuntu 20.04 LTS, the default archive tool things the file is corrupt if you don't.
