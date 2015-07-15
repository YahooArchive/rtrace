## Copyright 2015, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Get and print the register states
## Read the size argument to malloc
## Search the heap buffer for a DWORD

log.str "MALLOC() ======================================================"
@rtrace.print_registers
regs = @rtrace.get_registers

size = @rtrace.read64(@rtrace.get_sp(regs) + @rtrace.get_machine_word) if @rtrace.bits == 32
size = regs.rdi if @rtrace.bits == 64

@log.str "malloc(#{size})"

#locs = @rtrace.search_process(0x41414141)
locs = @rtrace.search_heap(0x41414141).flatten

if !locs.empty?
  log.str "0x41414141 found at:"
  locs.map do |l|
    l.map do |i|
      log.str " -> #{i.to_s(16)} #{@rtrace.get_mapping_name(i)}"
    end
  end
end

stack = @rtrace.get_stack_range
heap = @rtrace.get_heap_range
log.str "Stack => 0x#{stack.first.first.to_s(16)} ... 0x#{stack.first.last.to_s(16)}" if !stack.empty?
log.str "Heap => 0x#{heap.first.first.to_s(16)} ... 0x#{heap.first.last.to_s(16)}" if !heap.empty?
