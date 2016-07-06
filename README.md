Copyright 2015,2016, Yahoo! Inc.
Copyrights licensed under the New BSD License. See the accompanying LICENSE file in the project root folder for terms.

# What is it?

Disclaimer: THIS IS BETA CODE

Ruby code (with zero dependencies) for debugging native x86/x86_64 bit Linux binaries using the ptrace API. ARM support is planned but not yet finished.

Rtrace ships with Eucalyptus. A fully functional scriptable debugger that doubles as a unit test for Rtrace. Eucalyptus is scriptable and extendable, its not just a test harness. It ships with real world examples that work out of the box. It also includes some simple utilities for parsing ELF binaries.

The only dependency Rtrace has is FFI which can be easily installed with Ruby gems. FFI is maintained, supported, and incredibly powerful.

Rtrace contains an optional ELF parser that requires the bindata gem. The parser supports 32/64bit ELF objects but it has not been well tested. I welcome pull requests that improve its stability.

Rtrace is inspired by the Ragweed::Wraptux code which I wrote several years ago.

# TODO

* Rtrace currently lacks support for DWARF and has no disassembler. These things are a little beyond the scope of Rtrace. However Eucalyptus could see support for these in the near term. This would most likely include hooks for the Capstone engine.

# People

Rtrace is written by ChrisRohlf @ yahoo - inc . com

Ragweed was written by Thomas Ptacek, Timur Duehr, and Chris Rohlf

# License

Please see License.txt