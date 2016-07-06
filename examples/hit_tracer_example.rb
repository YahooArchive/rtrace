## Copyright 2015,2016, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Rtrace example hit tracer
## Please see Eucalyptus for a more comprehensive
## example of what is possible with rtrace

$: << File.dirname(__FILE__)

require 'rtrace'

pid = ARGV[0].to_i
bits = ARGV[1].to_i

if ARGV.size < 1 or pid == 0
	puts "hit_tracer_example.rb <PID>"
	exit
end

## Create an Rtrace instance
## by passing it a PID
d = Rtrace.new(pid)

## 32 or 64 process
d.bits = bits

## Attach to the PID
d.attach

## Create a block to run when our breakpoint is hit
f = Proc.new do |regs,rtrace|
	puts "Breakpoint Hit!"
	rtrace.print_registers
	puts "--------------------"
end

## Set the breakpoint
if d.bits == 64
	d.breakpoint_set(0x00000000004005bd, "foo", f)
else
	d.breakpoint_set(0x0804847d, "foo", f)
end

## Install all breakpoints
d.install_bps

## Continue the process
d.continue

## Loop using wait
catch(:throw) { d.loop }