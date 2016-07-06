#!/usr/bin/env ruby
## Copyright 2015,2016, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.
$: << File.dirname(__FILE__)

require 'ffi'
require 'rtrace'
require 'optparse'
require 'ostruct'
require 'open3'
require 'crash'
require 'common/config'
require 'common/output'
require 'common/common'

EUCALYPTUS_VERSION = "1.0"

class Eucalyptus
	attr_accessor :opts, :rtrace, :pid, :threads, :breakpoints, :so, :log, 
				  :event_handlers, :exec_proc, :rtrace_breakpoints, :bits,
				  :pid_stdin, :pid_stdout, :target_binary

	def initialize(opts)
		@opts = opts

		## PID wont be nil here, we checked
		## before ever creating this class.
		## It may be a numeric PID or a string
		## matching the name of the process
		@pid = opts[:pid]

		@target_binary = @pid if @pid.to_i == 0
		@bits = opts[:bits]
		@exec_proc = OpenStruct.new
		@breakpoints = []
		@threads = []
		@event_handlers = {}
		@so = {}
		@out = opts[:out]
		@log = EucalyptusLog.new(@out)
		@pid_stdin = nil
		@pid_stdout = nil

		## Parse Eucalyptus execute file
		parse_exec_proc(opts[:ep_file]) if opts[:ep_file]

		## Configure Eucalyptus using the DSL
		eval(File.read(opts[:dsl_file])) if opts[:dsl_file]

		if opts[:bp_file]
			if opts[:bp_file] !~ /\.rb/
				## Configure Eucalyptus with a config file
				parse_config_file(opts[:bp_file])
			else
				## Configure Eucalyptus with Ruby code
				config_dsl(opts[:bp_file])
			end
		end

		## @pid is set from the return value of popen
		launch_process if exec_proc.target.nil? == false

		if pid.kind_of?(String) or pid.to_i == 0
			@pid = EucalyptusImpl.find_by_regex(/#{pid}/).to_i
		else
			@pid = pid.to_i
		end

		if pid.nil? or pid == 0
			puts "Failed to find process: #{pid}"
			exit
		end

		## We need to attach to the target ASAP
		## if we called launch_process. We don't
		## want it to exit before we trace it
		@rtrace = EucalyptusImpl.new(pid, log)
		@rtrace.bits = bits
		@rtrace.attach

		## We have to invoke this one manually because
		## we havent called save_handlers yet
		@event_handlers["on_attach"].call if @event_handlers["on_attach"].nil? == false

		## Execute the code block supplied in the config
		exec_proc.code.call if exec_proc.code.kind_of?(Proc)

		@so = EucalyptusImpl.shared_libraries(pid)

		@threads = EucalyptusImpl.threads(pid)
		#self.which_threads

		@rtrace.save_threads(@threads)
		@rtrace.save_handlers(@event_handlers)

		self.set_breakpoints

		bp_count = 0
		@breakpoints.each {|b| bp_count+=1 if b.flag == true }

		@rtrace.save_breakpoints(@breakpoints)

		@rtrace.install_bps

		log.str "#{bp_count} Breakpoint(s) installed ..." if bp_count > 0

		## TODO: This should be more configurable
		o = 0
		o |= Ptrace::SetOptions::TRACEFORK if opts[:fork] == true
		o |= Ptrace::SetOptions::TRACEVFORK if opts[:fork] == true
		o |= Ptrace::SetOptions::TRACEVFORKDONE
		o |= Ptrace::SetOptions::TRACECLONE
		o |= Ptrace::SetOptions::TRACEEXIT
		o |= Ptrace::SetOptions::TRACEEXEC

		@rtrace.set_options(o) if o != 0

		@rtrace.continue

		trap("INT") do
			@rtrace.uninstall_bps
			@rtrace.dump_stats
			log.finalize
			@rtrace.native.kill(@rtrace.pid, Signal::SIGKILL) if opts[:kill]
			exit
		end

		## You probably want to save this somewhere.
		## Leave it commented if you're just hacking
		## on Eucalyptus
		#@pid_stdout.close if @pid_stdout != nil

		## Not catching exceptions here will
		## help catch bugs in Rtrace :)
		#begin
		   @rtrace.loop 
		#rescue Exception => e
		#    puts "Eucalyptus: #{e}"
		#end

		## This is commented out because the stats should
		## have been dumped already if we reached this
		## point through some debugger event
		#@rtrace.dump_stats
	end

	def set_breakpoints
		@breakpoints.each do |bp|

			if bp.addr.nil?
				bp.flag = false
				next
			end

			## Some breakpoints are position independent
			## and require knowing a library load address
			## before they can be set in the process
			if bp.lib
				so.each_pair do |k,v|
					puts "#{k.to_s(16)} => #{v} (#{rtrace.get_mapping_permissions(k)})"
					if v =~ /#{bp.lib}/ and rtrace.get_mapping_permissions(k) =~ /r\-x/
						bp.base = k
						break
					end
				end

				if bp.base != 0
					## We assume hex 0x string...
					bp.base = bp.base.to_i(16) if bp.base.kind_of?(String)
					bp.addr = bp.addr.to_i(16) if bp.addr.kind_of?(String)

					## Modify address now that we know base
					bp.addr = bp.base+bp.addr
				else
					log.str "Breakpoint #{bp.addr.to_s(16)} cannot be set because #{bp.lib} is not mapped"
					bp.flag = false
					next
				end
			end
			
			log.str "Setting breakpoint: 0x#{bp.addr.to_s(16)} #{bp.name} #{bp.lib}"

			## The block we pass breakpoint_set will
			## automagically call our Ruby code provided
			## via a config and check if we have hit our
			## maximum hit count. If we have then then
			## it is uninstalled for us
			@rtrace.breakpoint_set(bp.addr, bp.name, (Proc.new do
				eval(bp.code) if bp.code.kind_of?(String)
				bp.code.call if bp.code.kind_of?(Proc)

				bp.hits += 1

				if !bp.count.nil? and bp.hits.to_i >= bp.count.to_i
					log.str "Uninstalling breakpoint #{bp.name} at 0x#{bp.addr.to_s(16)}"
					bp.flag = false
					regs = @rtrace.get_registers
					@rtrace.breakpoint_clear(regs.eip-1) if @bits == 32
					@rtrace.breakpoint_clear(regs.rip-1) if @bits == 64
				end
			end ))

			bp.flag = true
		end
	end

	## Run the process specified in a config
	def launch_process
		## TODO: popen with env
		exec_proc.env.each_pair { |k,v| ENV[k] = v }
		@pid_stdin, @pid_stdout, t = Open3::popen2e("#{exec_proc.target} #{exec_proc.args}")
		@pid = t.pid
	end

	def check_bp_max(bp, ctx)
		if !bp.count.nil? and bp.hits.to_i >= bp.count.to_i
		   r = @rtrace.breakpoint_clear(ctx.eip-1)
		   bp.flag = false
		end
	end
end

## This class is how we inherit from Rtrace and control it
class EucalyptusImpl < Rtrace

	attr_accessor :log, :threads, :event_handlers, :rtrace_breakpoints

	def initialize(p, l)
		super(p)
		@log = l
		@threads = []
		@rtrace_breakpoints = []
		@event_handlers = {}
	end

	def save_breakpoints(b) @rtrace_breakpoints = b; end
	def save_threads(t) @threads = t; end
	def save_handlers(h) @event_handlers = h end

	def exec_eh_script(name)
		begin
			eval(@event_handlers[name]) if @event_handlers[name].kind_of?(String)
			@event_handlers[name].call if @event_handlers[name].kind_of?(Proc)
		rescue Exception => e
			puts "Error executing event handler script #{name} (#{e})"
		end
	end

	def dump_stats
		@rtrace_breakpoints.each do |bp|
			log.str "#{bp.addr.to_s(16)} - #{bp.name} was hit #{bp.hits} times"
		end
	end

	def on_fork_child(pid)
		@pid = pid
		exec_eh_script("on_fork_child")
		log.str "Parent process forked a child with pid #{pid}"
		super
	end

	def on_clone(tid)
		exec_eh_script("on_clone")
		log.str "New thread created with tid #{tid}"
		super
	end

	def on_sigchild
		exec_eh_script("on_sigchild")
		log.str "Got sigchild"
		super
	end

	def on_sigterm
		log.str "Process Terminated!"
		exec_eh_script("on_sigterm")
		dump_stats
		super
	end

	def on_segv
		log.str "Segmentation Fault!"
		exec_eh_script("on_segv")
		puts self.print_registers
		dump_stats
		Crash.new(self).exploitable?
		super
	end

	def on_breakpoint
		exec_eh_script("on_breakpoint")
		super
	end

	def on_exit(exit_code, pid)
		log.str "Thread (#{pid}) exited with return code: #{exit_code}!"
		exec_eh_script("on_exit")
		super(exit_code, pid)
		dump_stats
	end

	def on_illegal_instruction
		log.str "Illegal Instruction!"
		exec_eh_script("on_illegal_instruction")
		dump_stats
		puts self.print_registers
		Crash.new(self).exploitable?
		super
	end

	def on_iot_trap
		log.str "IOT Trap!"
		exec_eh_script("on_iot_trap")
		dump_stats
		puts self.print_registers
		Crash.new(self).exploitable?
		super
	end

	def on_sigbus
		log.str "SIGBUS"
		exec_eh_script("on_sigbus")
		dump_status
		puts self.print_registers
		Crash.new(self).exploitable?
		super
	end

	def on_attach
		exec_eh_script("on_attach")
		super
	end

	def on_detach
		exec_eh_script("on_detach")
		super
	end

	def on_sigtrap
		exec_eh_script("on_sigtrap")
		super
	end

	def on_continue
		## This would get noisy
		#log.str "Continuing..."
		exec_eh_script("on_continue")
		super
	end

	def on_sigstop
		exec_eh_script("on_sigstop")
		log.str "got sigstop"
		super
	end

	def on_signal(signal)
		exec_eh_script("on_signal")
		super
	end

	def on_single_step
		exec_eh_script("on_singlestep")
		super
	end

	def on_execve
		exec_eh_script("on_execve")
		super
	end

	def on_vfork_done
		exec_eh_script("on_vfork_done")
		super
	end

	def on_seccomp
		exec_eh_script("on_seccomp")
		super
	end

	def on_kill
		exec_eh_script("on_kill")
		super
	end

	def on_abort
		exec_eh_script("on_abort")
		super
	end

	def unhandled_signal(signal)
		exec_eh_script("unhandled_signal")
		super
	end
end

EUCALYPTUS_OPTS = {
	pid: nil,
	bits: 64,
	ep_file: nil,
	bp_file: nil,
	dsl_file: nil,
	out: STDOUT,
	fork: false,
	kill: false
}

opts = OptionParser.new do |opts|
	opts.banner = "Eucalyptus #{EUCALYPTUS_VERSION} | Yahoo 2014/2015\n\n"

	opts.on("-p", "--pid PID/Name", "Attach to this pid OR process name (ex: -p 12345 | -p gcalctool)") do |o|
		EUCALYPTUS_OPTS[:pid] = o
	end

	opts.on("-i", "--bits 32/64", "Is the target process 32 or 64 bit?") do |o|
		EUCALYPTUS_OPTS[:bits] = o.to_i
	end

	opts.on("-x", "--exec_proc [FILE]", "Launch a process according to the configuration found in this file") do |o|
		EUCALYPTUS_OPTS[:ep_file] = o
	end

	opts.on("-b", "--config_file [FILE]", "Read all breakpoints and handler event configurations from this file") do |o|
		EUCALYPTUS_OPTS[:bp_file] = o
	end

	opts.on("-d", "--dsl [FILE]", "Configure Eucalyptus using Ruby code (please see the README)") do |o|
		EUCALYPTUS_OPTS[:dsl_file] = o
	end

	opts.on("-o", "--output [FILE]", "Print all output to a file (default is STDOUT)") do |o|
		EUCALYPTUS_OPTS[:out] = File.open(o, "w") rescue (bail $!)
	end

	opts.on("-f", "Trace forked child processes") do |o|
		EUCALYPTUS_OPTS[:fork] = true
	end

	opts.on("-k", "Kill the target process when Eucalyptus exits") do |o|
		EUCALYPTUS_OPTS[:kill] = true
	end
end

opts.parse!(ARGV) rescue (STDERR.puts $!; exit 1)

if EUCALYPTUS_OPTS[:pid] == nil
	puts opts.help
	exit
end

Eucalyptus.new(EUCALYPTUS_OPTS)
