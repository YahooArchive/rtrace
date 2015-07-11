## Copyright 2015, Yahoo! Inc. 
## Copyrights licensed under the New BSD License. See the accompanying LICENSE file in the project root folder for terms.

## This is an example of using the Eucalyptus
## configuration DSL for debugging a program.
## It is heavily commented to help you
## understand what it does and why.

require './utils/parse_elf.rb'

malloc_addr = nil

## Open libc using the ELFReader class
## This path is hard coded and you might
## need to change it for the system you
## are on. Use ldd on your target binary
## to find the libc path it will use.
d = ELFReader.new("/lib/x86_64-linux-gnu/libc-2.19.so")

## Parse libc's ELF dynamic symbol table
## and locate the address of malloc(). We
## do this so we can set a breakpoint.
d.parse_dynsym do |sym|
	if d.get_symbol_type(sym) == "FUNC" and d.get_dyn_symbol_name(sym) =~ /__libc_malloc/
		malloc_addr = sym.st_value.to_i
		puts "malloc symbol found @ 0x#{malloc_addr.to_s(16)}" if !malloc_addr.nil?
		break
	end
end

## Instruct Eucalyptus to launch a 
## daemonized process
exec_file(
	## Path to the binary
	@target_binary,
	## Arguments to the process
	"some_argument",
	## Environment variables for the process
	{"env_var" => "some value"},
	## Ruby code to run upon execution
	Proc.new do
		puts "I just launched a process!"
end)

## Declare a handler for a ptrace attach event
event_handler "on_attach", (Proc.new do
	puts "I am now attached to the target (#{@pid})!"
end)

## Declare a handler for a segmentation fault signal
event_handler "on_segv", (Proc.new do
	puts "Oh no I segfaulted!"
end)

## Set a breakpoint for malloc in libc.
## We got this address earlier from the
## ELFReader class we created.
add_breakpoint(
	## Address (retrieved from ELFReader)
	malloc_addr,
	## Name of our breakpoint
	"malloc",
	## Library where it can be found
	"/lib/x86_64-linux-gnu/libc-2.19.so",
	## Number of hits before we uninstall it
	5,
	## Ruby code to run whenever the malloc()
	## breakpoint is hit by the program
	(Proc.new do
		## Let the user know we hit the breakpoint
		log.str "\nMALLOC() ======================================================"
		## Print the registers
		@rtrace.print_registers
		## Retrieve registers OpenStruct
		regs = @rtrace.get_registers

		## Extract the size value passed to malloc
		size = @rtrace.read64(@rtrace.get_sp(regs) + @rtrace.get_machine_word) if @rtrace.bits == 32
		size = regs.rdi if @rtrace.bits == 64

		## Display the call to malloc with size
		@log.str "malloc(#{size})"

		## Search the process for some values
		#locs = @rtrace.search_process(0x41414141)
		locs = @rtrace.search_heap(0x41414141).flatten

		## Print out where we found this value
		if !locs.empty?
		  	log.str "0x41414141 found at:"
			locs.map do |l|
			  l.map do |i|
			    log.str " -> #{i.to_s(16)} #{@rtrace.get_mapping_name(i)}"
			  end
			end
		end

		## Print the location of the stack and heap
		stack = @rtrace.get_stack_range
		heap = @rtrace.get_heap_range
		log.str "Stack => 0x#{stack.first.to_s(16)} ... 0x#{stack.last.to_s(16)}" if !stack.empty?
		log.str "Heap => 0x#{heap.first.to_s(16)} ... 0x#{heap.last.to_s(16)}" if !heap.empty?
end))