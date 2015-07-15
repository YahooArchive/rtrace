## Copyright 2015, Yahoo! Inc. 
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Rtrace example syscall tracer
require 'ffi'

$: << File.dirname(__FILE__)

require 'rtrace'

pid = ARGV[0].to_i
bits = 64

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

d.syscall_tracing = true

## Instruct rtrace to trace syscalls
d.syscall_trace(Proc.new do |regs,rtrace|
  puts "Syscall Executed"
  rtrace.print_registers
  puts "--------------------------------------"
  d.syscall_tracing = false
end)

puts "Continuing Process"
d.continue
catch(:throw) { d.loop }
