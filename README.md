# CWE_Detection

## Introduction

This project contains a collections of scripts that can detect many kinds of CWE automatically. It mainly based on what I do in a internship.

This can be a great example for `Ghidra` scripting, and it is well documented so you won't miss any important details(Hopefully 🤔).

## Requirements

There some common setup use should do before get hands on those scripts.

1. [Ghidra](https://ghidra-sre.org)

   Of course, because it is all use `Ghidra` as disassembly tool, you must had `Ghidra` installed on your machine.

   The installation can be Found on `Ghidra`'s official site, or if you use `macOS` with `homebrew` installed, you can simply run following command then you are ready to go.

   ```shell
    $ brew install ghidra
   ```

2. [ghidra_bridge](https://github.com/justfoxing/ghidra_bridge)(optional)

   In order to run python script, you may wanna to use ghidra_bridge. It's a must if you wanna running python script.

   `ghidra_bridge` use custom rpc call to communicate with a server installed in ghidra, syncing data between client and server. So you can use python3 to write all logic and don't need to worry syntax compatibility with `Jython`.

   To use `ghidra_bridge`, running following commands in your terminal, more details please refer to [ghidra_bridge](https://github.com/justfoxing/ghidra_bridge).

   ```shell
    # Install ghidra_bridge package
    $ pip3 install ghidra_bridge

    # Install the server as a ghidra plugin
    $ python3 -m ghidra_bridge.install_server ~/ghidra_scripts
   ```

   After installation of ghidra_bridge, open ghidra then start the server, happy exploring yourself.

3. [Z3 Prover](https://github.com/Z3Prover/z3)(optional)

   Some script may need a SMT Solver, install it with following commands if it needs one.

   ```shell
    $ pip3 install z3-solver
   ```

4. [Juliet Test Suite](https://samate.nist.gov/SRD/testsuite.php)(optional)

   If you wanna test what could the script do, I recommend you to take a look at [Juliet Test Suite](https://samate.nist.gov/SRD/testsuite.php).
   You can use it against scripts in this repo to see what result it would output. Or you can use it against your own tools.

   More details on [Juliet Test Suite](https://samate.nist.gov/SRD/testsuite.php) and the subfolder.

## Structure

The whole project arranged by the name of CWE, each folder contains a python(or java) script that you can run with the instructions alongside the script.

There is a list of all scripts:

- [CWE369_Divide_by_Zero](CWE369_Divide_by_Zero)
