## Copyright 2015, Yahoo! Inc. 
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## on_free example

## Get and print the register states
## Read the size argument to malloc
## Search the heap buffer for a DWORD

log.str "\nFREE() ======================================================"
@rtrace.print_registers
regs = @rtrace.get_registers
log.str "free(0x#{regs.rax.to_s(16)})"