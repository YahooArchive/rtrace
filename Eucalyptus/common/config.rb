## Copyright 2015, Yahoo! Inc. 
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

class Eucalyptus

	## Add a breakpoint
	## addr  - Address to set the breakpoint on,
	## 		  either absolute or from parse_elf
	## name  - Name of the breakpoint
	## lib   - Name of the library its found in
	## count - Number of times to hit the breakpoint
	## code  - A Ruby block for when the breakpoint is hit
	def add_breakpoint(addr, name="", lib=nil, count=0, code)
		if code.kind_of?(Proc) == false
			puts "add_breakpoint: I need a block! You gave me #{code.class}"
			return
		end

		bp = OpenStruct.new
		bp.base = 0
		bp.addr = addr
		bp.name = name
		bp.code = code
		bp.count = count
		bp.lib = lib.gsub(/[\s\n]+/, "")

		bp.hits = 0

		breakpoints.push(bp)
	end

	## Store a signal handler
	## event - signal string
	## code  - Ruby block
	def event_handler(event, code)
		hdlrs = %w[ on_attach on_detach on_single_step on_syscall_continue on_continue on_exit 
					on_signal on_sigint on_segv on_illegal_instruction on_sigtrap on_fork_child
					on_sigchild on_sigterm on_sigstop on_iot_trap on_stop on_execve on_vfork_done
					on_seccomp on_kill on_abort on_sigbus unhandled_signal on_syscall ]

		if hdlrs.include?(event) == false
			puts "event_handler: I don't support event #{event}"
			return
		end

		if code.kind_of?(Proc) == false
			puts "event_handler: I need a block! You gave me #{code.class}"
			return
		end

		event_handlers.store(event, code)
	end

	## Eucalyptus supports a DSL for configuration
	## This is a wrapper that evals a configuration
	## script. That script should call the methods
	## above this comment.
	def config_dsl(file)
		eval(File.read(file))
	end

	def parse_config_file(file)
		return if file.nil?

		fd = File.open(file)

		## All the handlers a user can script
		## There is no specific order to these
		hdlrs = %w[ on_attach on_detach on_single_step on_syscall_continue on_continue on_exit 
					on_signal on_sigint on_segv on_illegal_instruction on_sigtrap on_fork_child
					on_sigchild on_sigterm on_sigstop on_iot_trap on_stop on_execve on_vfork_done
					on_seccomp on_kill on_abort on_sigbus unhandled_signal on_syscall ]

		lines = fd.readlines
		lines.map { |x| x.chomp }

		lines.each do |tl|
			next if tl[0].chr == ';' or tl.nil?

			bp = OpenStruct.new
			bp.base = 0
			bp.flag = true
			bp.hits = 0
			bp.count = nil

			r = tl.split(",")

			if r.size < 2 then next end

			r.each do |e|
				hdlrs.each do |l|
					if e.match(/#{l}=/)
						i,p = tl.split("=")
						i.gsub!(/[\s\n]+/, "")
						p.gsub!(/[\s\n]+/, "")
						p = File.read(p)
						event_handlers.store(i,p)
						next
					end
				end

				if e.match(/addr=/)
					addr = e.split("bp=").last
					bp.addr = addr.gsub(/[\s\n]+/, "")
				end

				if e.match(/name=/)
					name = e.split("name=").last
					bp.name = name.gsub(/[\s\n]+/, "")
				end

				if e.match(/count=/)
					count = e.split("count=").last
					bp.count = count.to_i
				end

				if e.match(/code=/)
					code = e.split("code=").last
					c = code.gsub(/[\s\n]+/, "")
					r = File.read(c)
					bp.code = r
				end

				if e.match(/lib=/)
					lib = e.split("lib=").last
					bp.lib = lib.gsub(/[\s\n]+/, "")
				end
			end

			bp.hits = 0
			breakpoints.push(bp)
		end
	end

	## Execute a program
	## path - Path on disk to the file
	## args - Array of arguments to pass
	## env  - Hash of environment variables
	## code - Optional Ruby block to run
	def exec_file(path, args, env, code=nil)
		if args.kind_of?(String) == false and env.kind_of?(Hash) == false
			puts "exec_file: args must be an Array and env must be a Hash. (args=#{args.class}) (env=#{env.class})"
			return
		end

		exec_proc.args = ""
		exec_proc.env = {}
		exec_proc.target = path
		exec_proc.args = args
		exec_proc.env = env
		exec_proc.code = code if code.kind_of?(Proc)
	end

	def parse_exec_proc(file)
		return if file.nil?

		fd = File.open(file)
		proc_control = %w[ target args env ]

		lines = fd.readlines
		lines.map { |x| x.chomp }

		exec_proc.args = Array.new
		exec_proc.env = Hash.new

		lines.each do |tl|
			if tl[0].chr == ';' or tl.nil? then next end

			k,v,l = tl.split(':')

			if k.match(/target/)
				## Dirty little hack if a : is used
				## in the target path
				v = "#{v}:#{l}" if !l.nil?
				v.gsub!(/[\n]+/, "")
				v.gsub!(/[\s]+/, "")
				exec_proc.target = v
			end

			if k.match(/args/)
				v.gsub!(/[\n]+/, "")
				exec_proc.args = v
			end

			if k.match(/env/)
				v.gsub!(/[\n]+/, "")
				k,v = v.split('=')
				k.gsub!(/[\s]+/, "")
				exec_proc.env.store(k,v)
			end
		end
	end
end
