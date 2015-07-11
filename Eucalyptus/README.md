Copyright 2014, Yahoo! Inc. 
Copyrights licensed under the New BSD License. See the
accompanying LICENSE file in the project root folder for terms.

### Eucalyptus

## What is it?

	Eucalyptus is a modern, native code debugger for x86/x86_64 with zero dependencies.

	Eucalyptus can be a dynamic hit tracer, an in memory fuzzer or a simple scriptable debugger.
	All you need to do is give it a configuration file telling it what breakpoints to
	set, events to hook and what Ruby scripts to execute when those things occur.

	Eucalyptus showcases the best part about Rtrace: cross platform debugging. I originally
	wrote Eucalyptus as a small Rtrace script that kept stats on the functions my fuzzers
	were triggering in a target process. This told me what code paths my fuzzer was
	reaching and which ones it wasn't. It only took a few hours to make it work on all Rtrace
	supported platforms, and since then it has grown into a much more capable tool. It now
	supports configuration files for breakpoints, event handler scripts and more.

	We have included several working examples with Eucalyptus so that you aren't lost the first
	time you try it. If you develop some useful scripts with it let us know and we can make
	them part of the default package.

## Supported Platforms

	Eucalyptus is supported and has been tested on the following platforms:

	Intel x86, x86_64

	Ubuntu 14 / RHEL 6

	Ruby 1.9.x
	Ruby 2.x

## Features

	- It is the reference implementation and a great unit test for Rtrace
	- Easy configuration files you can write by hand or generate
	- Run Ruby scripts with full access to the debugger core when breakpoints are hit
	- Run Ruby scripts when specific debugger events occur such as signals
	- Extend Eucalyptus through on_{event} handlers or output.rb with minimal code changes
	- Eucalyptus comes with a few example breakpoint scripts that actually work

## Dependencies

	Eucalyptus has no dependencies. No really it doesn't. I know thats hard for you
	to believe because its written in Ruby but its true. No gems, no broken junk that
	was developed under 1.8 and no longer works. Nothing. If you have this code then
	you have everything you need to run it.

## Usage

$ ruby eucalyptus.rb -h

Eucalyptus 1.0 | Yahoo 2014/2015

    -p, --pid PID/Name         Attach to this pid OR process name (ex: -p 12345 | -p gcalctool)
    -i, --bits 32/64           Is the target process 32 or 64 bit?
    -x, --exec_proc [FILE]     Launch a process according to the configuration found in this file
    -b, --config_file [FILE]   Read all breakpoints and handler event configurations from this file
    -d, --dsl [FILE]           Configure Eucalyptus using Ruby code (please see the README)
    -o, --output [FILE]        Print all output to a file (default is STDOUT)
    -f                         Trace forked child processes
    -k                         Kill the target process when Eucalyptus exits

## Configuration File Example

	All recognized configuration file keywords are documented below. The order does not
	matter but each line represents a unique breakpoint.

	addr - An address where the debugger should set a breakpoint
	name - A name describing the breakpoint, typically a symbol or function name
	lib - An optional library name indicating where the symbol can be found
	count - Number of times to let this breakpoint hit before uninstalling it
	code - Location of a script that holds Ruby code to be executed when the breakpoint hits

	Example:

	addr=0x12345678, name=function_name, lib=ncurses.so.5.1, count=1, code=scripts/ncurses_trace.rb
	name=malloc, lib=/lib/tls/i686/cmov/libc-2.11.1.so, count=10, addr=0x006ff40, code=scripts/malloc_linux.rb

## Process Launching Configurations

	You can instruct Eucalyptus to launch a target process with arguments and environment
	variables of your choosing. Eucalyptus takes the -x flag along with a filename containing
	your configuration. Be aware that Eucalyptus currently uses exec() to launch processes.
	This means stdout will be written to by the new process. This could probably use some work.

	Process launching configuration keywords

	target - The location of the application you want to run
	args - A string of arguments to pass to the application
	env - A string of environment variables for the application

	target: /usr/bin/gcalctool
	args: -s 1+1
	env: MALLOC_CHECK_=4
	env: BLAH=test
	env: MYLIBPATH=/usr/lib

## Breakpoint Scripts

	Eucalyptus supports breakpoint scripts that run when a breakpoint you have specified is executed. These
	can be specified using the 'code=' keyword in your Eucalyptus configuration file (see above).
	These scripts run within the scope of Eucalyptus and the Rtrace breakpoint. This means your scripts
	have access to all the helper methods and instance variables Rtrace makes available. Documenting
	each of these is going to take a bit of time but heres some stuff you can start with.

	Helper Methods:

	(please refer to Rtrace sources for now http://github.com/struct/Rtrace)

	Instance Variables:

	@Rtrace - The Rtrace instance, use this to call all Rtrace public methods

## Event Handlers Configuration Example

	Event handler scripts work just like breakpoint scripts. They have full access to the debugger
	but are triggered when specific debug events occur such as 'on_breakpoint'. See handlers.rb for
	how they are implemented and how you can overload or hook them.

	Keywords for configuration files:

	on_fork_child
	on_sigchild
	on_sigterm
	on_segv
	on_breakpoint
	on_exit
	on_illegal_instruction
	on_iot_trap
	on_attach
	on_detach
	on_sigtrap
	on_continue
	on_sigstop
	on_signal
	on_single_step

	This example will run the on_segv.rb script whenever the on_segv debug event occurs:

	on_segv=scripts/on_segv.rb

## Examples

	Heres some example output from Eucalyptus running on Ubuntu Linux:

	chris@ubuntu:/# ruby Eucalyptus.rb -b example_configuration_files/generic_ubuntu_libc_trace.txt -p test
	Eucalyptus ...
	Setting breakpoint: [ 0x0964f40, malloc /lib/tls/i686/cmov/libc-2.11.1.so ]
	Setting breakpoint: [ 0x08055590, mp_add ]
	Setting breakpoint: [ 0x0971830, wmemcpy /lib/tls/i686/cmov/libc-2.11.1.so ]
	Setting breakpoint: [ 0x0969f20, memcpy /lib/tls/i686/cmov/libc-2.11.1.so ]
	Setting breakpoint: [ 0x0964e60, free /lib/tls/i686/cmov/libc-2.11.1.so ]
	Setting breakpoint: [ 0x09b2de0, read /lib/tls/i686/cmov/libc-2.11.1.so ]
	Setting breakpoint: [ 0x09b2e60, write /lib/tls/i686/cmov/libc-2.11.1.so ]
	^CDumping stats
	0x0a3cf40 - malloc | 5279
	0x08055590 - mp_add | 0
	0x0a49830 - wmemcpy | 0
	0x0a41f20 - memcpy | 0
	0x0a3ce60 - free | 8385
	0x0a8ade0 - read | 0
	0x0a8ae60 - write | 0
	... Done!

## Useful Tips

	- If you need to declare some global variables you should do it in an on_attach
	  script. This code will only run once when the debugger attaches to the target.

## Disassembly

	Rtrace and Eucalyptus do not ship with a disassembly library. We feel thats outside the
	scope of a core debugger library. We do however recommend the following Ruby disassembly libraries:

	https://github.com/bnagy/crabstone - FFI Capstone wrapper
	https://github.com/sophsec/ffi-udis86 - FFI UDis86 library
	https://github.com/struct/frasm - A Ruby C extension for distorm64

## Todo and Ideas

	- All configuration should be done via ruby Rtrace DSL scripts, not config files
		- This should include breakpoints, ptrace options and everything else
		- Started but not finished
	- Support setting bits from within conf file
	- Lots of helper scripts for breakpoints such as heap inspection, in memory fuzzing, SSL reads etc.
	- Helper methods and better named instance variables for making breakpoint scripts easier to write
	- Better output such as graphviz, statistics, function arguments etc...
	- Redis database support for offline analysis of output
	- Cleaner support for launching processes
	- Continous re-attach to any targets that match the process name

## Who

Eucalyptus was written by Chris Rohlf in 2014/2015
Rtrace was written by Chris Rohlf in 2014/2015
