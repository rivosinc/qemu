============================
Rivos QEMU Profiling Plugins
============================

This directory contains a set of qemu plugins which can be used for profiling an application running in qemu.  These plugins are built and included in the rivos-sdk by default.  Many of the extensions are provided by upstream qemu, and are `publicly documented <https://www.qemu.org/docs/master/devel/tcg-plugins.html>`_.

The three plugins which we have either added or substaintially changed are: `bbvgen`, `cache`, and `pctrace`.

bbvgen
  A tool for collecting "basic block vectors" in the format defined by the `simpoint <https://cseweb.ucsd.edu/~calder/simpoint/>`_ tool.  Used to feed `our copy of simpoint <https://gitlab.ba.rivosinc.com/rv/sw/ext/simpoint>`_ when generating snapshots for analysis with gem5.  Also collects a json file with various adhoc statistics and information.  (See example usage below.)

cache
  A tool for modeling cache access behavior inside a qemu run.  Many of the cache parameters are runtime configurable, but we have also made changes to extend the simulators cache architecture.

insn
  A tool for counting dynamic instruction count and size histograms.  Copied from upstream tests/plugin without changes.

pctrace
  A tool for collecting a full execution trace of a running program.  The output file is a gzipped text file whose format is defined below.


Basic Usage
-----------

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

The insn plugin can be used to count the number of dynamic instructions executed.

.. code-block:: console

  /rivos/qemu/bin/qemu-riscv64 -plugin /home/preames/rivos-qemu/build/contrib/plugins/libinsn.so,inline=true -d plugin ./coremark.riscv 0 0 0 6000

Note that this example is not thread safe; to get reliable counts on multi threaded applications you need to remove "inline=true", but that also causes *much* slower runtimes.

Collecting Instruction Size Histogram
=====================================

The insn plugin can also print a summary of the sizes (in bytes) of executed instructions.  This is helpful when you're interested in e.g. compressed instruction usage.

.. code-block:: console

  /rivos/qemu/bin/qemu-riscv64 -plugin /home/preames/rivos-qemu/build/contrib/plugins/libinsn.so,inline=true,sizes=true -d plugin ./coremark.riscv 0 0 0 6000

Sample output::

  len 2 bytes: 5380 insns
  len 4 bytes: 4231 insns

  
Collecting Dynamic Instruction Count (Altenate Version)
=======================================================

The bvvgen plugin collects (among many other details) the dynamic instruction count of the executed program.

.. code-block:: console

  /rivos/qemu/bin/qemu-riscv64 -plugin /rivos/qemu/plugins/libbbvgen.so,bbv=$PWD/bbvvs.gz,bbvi=$PWD/bbvi.gz ./coremark.riscv 0 0 0 40000

In the generated bbvi.gz file, you will find a single json file.  That file contains (towards the bottom) an entry with the key "instructions", and an integer value which should be in the 10s of billions for this test.  That's your dynamic instruction count.
  
A couple of potential gotchas here:

* Both options (bbv, and bbvi) are required despite the fact we only care about one.  The order of appearance in the command line also appears important.
* Make sure you include the ".gz" suffix.  At least on Ubuntu 20.04 LTS, the default archive tool things the file is corrupt if you don't.

Using pctrace for adhoc workflows
=================================

The `pctrace` plugin gives a building block from which many adhoc flows can be constructed.  The pctrace output format is a gzipped text file whose contents look like the following:

.. code-block::

  0x0000000000010c30    022000ef          jal             ra,34           # 0x10c52
  0x0000000000010c52    00065197          auipc           gp,413696       # 0x75c52
  0x0000000000010c56    43e18193          addi            gp,gp,1086
  0x0000000000010c5a    8082              ret
  0x0000000000010c34    87aa              mv              a5,a0
  0x0000000000010c36    00000517          auipc           a0,0            # 0x10c36
  0x0000000000010c3a    8c850513          addi            a0,a0,-1848
  0x0000000000010c3e    6582              ld              a1,0(sp)
  0x0000000000010c40    0030              addi            a2,sp,8
  0x0000000000010c42    ff017113          andi            sp,sp,-16
  0x0000000000010c46    4681              mv              a3,zero
  0x0000000000010c48    4701              mv              a4,zero
  0x0000000000010c4a    880a              mv              a6,sp
  0x0000000000010c4c    4ab010ef          jal             ra,7338         # 0x128f6
  0x00000000000128f6    00158713          addi            a4,a1,1
  0x00000000000128fa    7159              addi            sp,sp,-112
  0x00000000000128fc    070e              slli            a4,a4,3

The fields from left to right are: address of instruction (PC), bytes of instruction, and disassembled form.

This example was collected via the following command:

.. code-block:: console

  /rivos/qemu/bin/qemu-riscv64 -plugin /rivos/qemu/plugins/libpctrace.so,out=$PWD/trace ./coremark.riscv 0 0 0 100

*Note the use of a much smaller iteration count*.  Collecting a full trace is quite slow, and the resulting files are massive.  The compressed trace files are roughly 90-120MB per minute of execution.  The uncompressed form is around 10GB per execution minute.

Let's run through some sample commands.  All of these assume that you have uncompressed the trace, and that the resulting textual tracefile is called `data`.

.. code-block:: console

  # To (very slowly) get the dynamic instruction count
  $ wc data

  # to count the number of unique PCs executed
  $ sort data | uniq | wc

  # To count how many times each opcode was executed
  $ cat data | tr -s ' ' | cut -f 3 -d ' ' | sort | uniq -c

  # Show a poorman's profile (by instruction count)
  cat data | sort | uniq -c

The last command deserves a special callout.  It displays a textual output which prefixes each unique assembly line (in pc order) with the number of times it was executed.  This is very useful for quickly identifying hot regions in programs.

Output Formats
--------------

bbvgen bbv
==========

The format of this file is defined to match the input format of the `simpoint <https://cseweb.ucsd.edu/~calder/simpoint/>` tool.

bbvgen bbvi
===========

This is an adhoc collection of statistics and information in (gzipped) JSON format.

pctrace
=======

The pctrace output format is a gzipped text file whose contents look like the following:

.. code-block::

  0x0000000000010c30    022000ef          jal             ra,34           # 0x10c52
  0x0000000000010c52    00065197          auipc           gp,413696       # 0x75c52
  0x0000000000010c56    43e18193          addi            gp,gp,1086
  0x0000000000010c5a    8082              ret
  0x0000000000010c34    87aa              mv              a5,a0
  0x0000000000010c36    00000517          auipc           a0,0            # 0x10c36
  0x0000000000010c3a    8c850513          addi            a0,a0,-1848
  0x0000000000010c3e    6582              ld              a1,0(sp)
  0x0000000000010c40    0030              addi            a2,sp,8
  0x0000000000010c42    ff017113          andi            sp,sp,-16
  0x0000000000010c46    4681              mv              a3,zero
  0x0000000000010c48    4701              mv              a4,zero
  0x0000000000010c4a    880a              mv              a6,sp
  0x0000000000010c4c    4ab010ef          jal             ra,7338         # 0x128f6
  0x00000000000128f6    00158713          addi            a4,a1,1
  0x00000000000128fa    7159              addi            sp,sp,-112
  0x00000000000128fc    070e              slli            a4,a4,3

The fields from left to right are: address of instruction (PC), bytes of instruction, and disassembled form.
