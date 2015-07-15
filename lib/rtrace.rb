## Copyright 2015, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

RTRACE_VERSION = "1.4"

## This ugly code is from the Ragweed project. It is
## required to support struct style access of FFI fields
module FFIStructInclude
  if RUBY_VERSION < "1.9"
    def methods regular=true
      (super + self.members.map{|x| [x.to_s, x.to_s+"="]}).flatten
    end
  else
    def methods regular=true
      (super + self.members.map{|x| [x, (x.to_s+"=").intern]}).flatten
    end
  end

  def method_missing meth, *args
    super unless self.respond_to? meth
    if meth.to_s =~ /=$/
      self.__send__(:[]=, meth.to_s.gsub(/=$/,'').intern, *args)
    else
      self.__send__(:[], meth, *args)
    end
  end

  def respond_to? meth, include_priv=false
    # mth = meth.to_s.gsub(/=$/,'')
    !((self.methods & [meth, meth.to_s]).empty?) || super
  end
end

NULL = nil

## x86 registers
class PTRegs32 < FFI::Struct
  include FFIStructInclude
  layout :ebx, :ulong,
    :ecx, :ulong,
    :edx, :ulong,
    :esi, :ulong,
    :edi, :ulong,
    :ebp, :ulong,
    :eax, :ulong,
    :xds, :ulong,
    :xes, :ulong,
    :xfs, :ulong,
    :xgs, :ulong,
    :orig_eax, :ulong,
    :eip, :ulong,
    :xcs, :ulong,
    :eflags, :ulong,
    :esp, :ulong,
    :xss, :ulong
end

## x64 Registers
class PTRegs64 < FFI::Struct
  include FFIStructInclude
  layout :r15, :ulong,
    :r14, :ulong,
    :r13, :ulong,
    :r12, :ulong,
    :rbp, :ulong,
    :rbx, :ulong,
    :r11, :ulong,
    :r10, :ulong,
    :r9, :ulong,
    :r8, :ulong,
    :rax, :ulong,
    :rcx, :ulong,
    :rdx, :ulong,
    :rsi, :ulong,
    :rdi, :ulong,
    :orig_rax, :ulong,
    :rip, :ulong,
    :cs, :ulong,
    :eflags, :ulong,
    :rsp, :ulong,
    :ss, :ulong,
    ## There is something very wrong here. FFI/Ruby
    ## will clobber the structure at the end of this
    ## and cause heap checks to fail. I don't think
    ## this is an rtrace bug because PTRegs64 has
    ## .size() and we use FFI::MemoryPointer
    :pad1, :ulong,
    :pad2, :ulong,
    :pad3, :ulong,
    :pad4, :ulong
end

## __ptrace_peeksiginfo_args Structure
class PeekSigInfoArgs < FFI::Struct
  include FFIStructInclude
  layout :off, :uint64,
    :flags, :uint32,
    :nr, :int
end

module PeekSigInfoFlags
  PEEKSIGINFO_SHARED = (1 << 0)
end

module Ptrace
  TRACE_ME = 0
  PEEK_TEXT = 1
  PEEK_DATA = 2
  PEEK_USER = 3
  POKE_TEXT = 4
  POKE_DATA = 5
  POKE_USER = 6
  CONTINUE = 7
  KILL = 8
  STEP = 9
  GETREGS = 12
  SETREGS = 13
  GETFPREGS = 14
  SETFPREGS = 15
  ATTACH = 16
  DETACH = 17
  GETFPXREGS = 18
  SETFPXREGS = 19
  SYSCALL = 24
  SETOPTIONS = 0x4200
  GETEVENTMSG = 0x4201
  GETSIGINFO = 0x4202
  SETSIGINFO = 0x4203
  GETREGSET = 0x4204
  SETREGSET = 0x4205
  SEIZE = 0x4206
  INTERRUPT = 0x4207
  LISTEN = 0x4208
  PEEKSIGINFO = 0x4209
end

# Use ::Signal
module Signal
  SIGHUP = 1
  SIGINT = 2
  SIGQUIT = 3
  SIGILL = 4
  SIGTRAP = 5
  SIGSYSTRAP = (SIGTRAP | 0x80)
  SIGABRT = 6
  SIGIOT = 6
  SIGBUS = 7
  SIGFPE = 8
  SIGKILL = 9
  SIGUSR1 = 10
  SIGSEGV = 11
  SIGUSR2 = 12
  SIGPIPE = 13
  SIGALRM = 14
  SIGTERM = 15
  SIGSTKFLT = 16
  SIGCHLD = 17
  SIGCONT = 18
  SIGSTOP = 19
  SIGTSTP = 20
  SIGTTIN = 21
  SIGTTOU = 22
  SIGURG = 23
  SIGXCPU = 24
  SIGXFSZ = 25
  SIGVTALRM = 26
  SIGPROF = 27
  SIGWINCH = 28
  SIGIO = 29
  SIGPOLL = SIGIO
  SIGPWR = 30
  SIGSYS = 31
  SIGUNUSED = 31
end

module Ptrace::SetOptions
  TRACESYSGOOD = 0x00000001
  TRACEFORK = 0x00000002
  TRACEVFORK = 0x00000004
  TRACECLONE = 0x00000008
  TRACEEXEC = 0x00000010
  TRACEVFORKDONE = 0x00000020
  TRACEEXIT = 0x00000040
  TRACESECCOMP = 0x00000080 ## Kernel 3.x
  EXITKILL = 0x00100000 ## Kernel 3.x
  MASK = 0x0000007f
end

module Ptrace::EventCodes
  FORK = (Signal::SIGTRAP | (1 << 8))
  VFORK = (Signal::SIGTRAP | (2 << 8))
  CLONE = (Signal::SIGTRAP | (3 << 8))
  EXEC = (Signal::SIGTRAP | (4 << 8))
  VFORK_DONE = (Signal::SIGTRAP | (5 << 8))
  EXIT = (Signal::SIGTRAP | (6 << 8))
  SECCOMP = (Signal::SIGTRAP | (7 << 8))
end

module Wait
  NOHANG = 0x00000001
  UNTRACED = 0x00000002
  EXITED = 0x00000004
  STOPPED = 0x00000002
  CONTINUED = 0x00000008
  NOWAIT = 0x01000000
  NOTHREAD = 0x20000000
  WALL = 0x40000000
  CLONE = 0x80000000
end

module PagePermissions
  PROT_NONE  = 0x0
  PROT_READ  = 0x1
  PROT_WRITE = 0x2
  PROT_EXEC  = 0x4
  PROT_GROWSDOWN = 0x01000000
  PROT_GROWSUP   = 0x02000000
end

module Libc
  extend FFI::Library
  ffi_lib FFI::Library::LIBC
  attach_function 'ptrace', [ :ulong, :pid_t, :ulong, :ulong ], :long
  attach_function 'wait', [ :pointer ], :int
  attach_function 'waitpid', [ :int, :pointer, :int ], :int
  attach_function 'kill', [ :int, :int ], :int
end

class Native
  def initialize
    ## empty
  end

  ## pid_t wait(int *status);
  def wait
    p = FFI::MemoryPointer.new(:int, 1)
    FFI.errno = 0
    pid = Libc.wait p
    raise SystemCallError.new "wait", FFI.errno if pid == -1
    status = p.get_int32(0)
    [pid, status]
  end

  ## pid_t waitpid(pid_t pid, int *status, int options);
  ## OLD DEPRECATED BUSTED UP JUNK
  def waitpid pid, opts = 0
    p = FFI::MemoryPointer.new(:int, 1)
    FFI.errno = 0
    r = Libc.waitpid pid, p, opts
    raise SystemCallError.new "waitpid", FFI.errno if r == -1
    status = p.get_int32(0)
    [r, status]
  end

  ## int kill(pid_t pid, int sig);
  def kill pid, sig
    FFI.errno = 0
    r = Libc.kill pid, sig
    raise SystemCallError.new "kill", FFI.errno if r == -1
    r
  end

  ## long native.ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
  def ptrace req, pid, addr, data
    FFI.errno = 0
    r = Libc.ptrace req, pid, addr, data
    raise SystemCallError.new "ptrace", FFI.errno if r == -1 and !FFI.errno.zero?
    self.kill(pid, Signal::SIGCONT)
    r
  end
end

## The Rtrace class. See examples directory or the
## Eucalyptus tool for how to use this class
class Rtrace
  attr_reader :status, :exited, :signal
  attr_accessor :breakpoints, :mapped_regions, :process, :use_ptrace_for_search,
    :bits, :native, :syscall_tracing, :syscall_block, :pid, :tids

  ## Each breakpoint is represented by one of these class instances.
  class Breakpoint

    INT3 = 0xCC

    attr_accessor :orig, :bppid, :function, :installed, :native
    attr_reader :addr

    ## ip: address to set a breakpoint on
    ## callable: Proc to be called when your breakpoint executes
    ## p: process ID
    ## name: name of breakpoint
    ## n: class instance for calling into Libc
    def initialize(ip, callable, p, name = "", n)
      @bppid = p
      @function = name
      @addr = ip
      @callable = callable
      @installed = false
      @orig = 0
      @native = n
    end

    def install
      @orig = native.ptrace(Ptrace::PEEK_TEXT, @bppid, @addr, 0)
      if @orig != -1
        n = (@orig & ~0xff) | INT3;
        native.ptrace(Ptrace::POKE_TEXT, @bppid, @addr, n)
        @installed = true
      else
        @installed = false
      end
    end

    def uninstall
      if @orig != INT3
        a = native.ptrace(Ptrace::POKE_TEXT, @bppid, @addr, @orig)
        @installed = false
      end
    end

    def installed?; @installed; end
    def call(*args); @callable.call(*args) if @callable != nil; end
  end ## end Breakpoint

  ## p: pid of process to be debugged
  def initialize(pid)
    if p.to_i.kind_of? Fixnum
      @pid = pid.to_i
    else
      raise "Please supply a PID"
    end

    @bits = 32 ## defaults to 32
    @installed = false
    @attached = false
    @use_ptrace_for_search = false
    @syscall_tracing = false
    @syscall_block = nil
    @exited = false
    @tids = []

    @mapped_regions = Hash.new
    @breakpoints = Hash.new
    @native = Native.new
  end

  def try_method(m, *a)
    send m, *a if respond_to? m
  end

  ## Find a PID by string/regex
  def self.find_by_regex(rx)
    rx = /#{rx}/ if rx.kind_of?(String)
    my_pid = Process.pid
    Dir.glob("/proc/*/cmdline").each do |x|
      x_pid = x.match(/\d+/).to_s.to_i
      next if x =~ /self/ or x_pid == my_pid
      begin
        File.read(x).each_line do |ln|
          return x_pid if ln =~ rx
        end
      rescue SystemCallError => e
        ## Processes die, we don't care
      end
    end
    nil
  end

  ## Returns an array of all PIDs
  ## currently in procfs
  def self.get_pids
    pids = []
    rx = /#{rx}/ if rx.kind_of?(String)
    my_pid = Process.pid
    Dir.glob("/proc/*").each do |x|
      next if x =~ /self/ or x.match(/\d+/) == nil
      begin
        pids.push(x.match(/\d+/).to_s.to_i)
      rescue SystemCallError => e
        ## Processes die, we don't care
      end
    end
    pids
  end

  def install_bps
    @breakpoints.each do |k,v|
      v.install
    end
    @installed = true
  end

  def uninstall_bps
    @breakpoints.each do |k,v|
      v.uninstall
    end
    @installed = false
  end

  def installed?; @installed; end
  def attached?; @attached; end

  ## This has not been fully tested yet
  def set_options(option)
    r = native.ptrace(Ptrace::SETOPTIONS, @pid, 0, option)
  end

  ## Attach calls install_bps so dont forget to call breakpoint_set
  ## BEFORE attach or explicitly call install_bps
  def attach
    r = native.ptrace(Ptrace::ATTACH, @pid, 0, 0)
    s, q = Process.waitpid2(@pid, Wait::WALL|Wait::UNTRACED|Wait::NOHANG)

    if r != -1
      @attached = true
      on_attach
      self.install_bps if @installed == false
    else
      raise "Attach failed!"
    end
    return r
  end

  ## A helper for tracing syscalls
  ## flag - true if we want to trace syscalls
  ## f - The block to execute when
  def syscall_trace(f)
    @syscall_block = f
    native.ptrace(Ptrace::SETOPTIONS, @pid, 0, Ptrace::SetOptions::TRACESYSGOOD)

    ## By calling this helper we assume you
    ## want to trace syscalls. When you want
    ## to stop just set Rtrace.syscall_tracing = false
    @syscall_tracing = true

    while @syscall_tracing == true
      native.ptrace(Ptrace::SYSCALL, @pid, 0, 0)
      self.wait
    end

    ## Reaching here means you set syscall_tracing
    ## to false, so we clear all that for you. However
    ## you will have to call Rtrace::continue
    @syscall_tracing = false
    @syscall_block = nil
    native.ptrace(Ptrace::SETOPTIONS, @pid, 0, 0)
  end

  ## Returns an array of TID's from procfs
  def self.threads(pid)
    a = []
    begin
      a = Dir.entries("/proc/#{pid}/task/")
      a.delete_if do |x|
        x == '.' or x == '..'
      end
    rescue SystemCallError => e
      puts "No such PID: #{pid}"
    end
    a
  end

  # This method returns a hash of mapped regions
  # The hash is also stored as @mapped_regions
  # key = Start address of region
  # value = Size of the region
  def mapped
    @mapped_regions.clear if @mapped_regions
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        e = l.split(' ',2).first
        s,e = e.split('-').map{|x| x.to_i(16)}
        sz = e - s
        @mapped_regions.store(s, sz)
      end
    end
    @mapped_regions
  end

  ## Return a name for a range if possible. greedy match
  ## returns the first found
  def get_mapping_name(val)
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        range, perms, offset, dev, inode, pathname = l.chomp.split(" ")

        ## Dirty temporary hack to determine if
        ## process is 32 or 64 bit. Ideally the
        ## consumer of Rtrace should set (Rtrace.bits)
        @bits = 64 if @bits == 0 and pathname =~ /\/lib\/x86_64/

        base, max = range.split('-').map{|x| x.to_i(16)}

        return pathname if base <= val and val <= max
      end
    end
    nil
  end

  ## Return a range via mapping name
  def get_mapping_by_name(name)
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        res = l.scan(name)
        if res.empty? == false
          res = res.first
          range = l.chomp.split(" ").first

          if res == name
            return range.split('-').map{|x| x.to_i(16)}
          end
        end
      end
    end
    return []
  end

  ## Returns the permissions for an address
  ## e.g. r-x, rwx rw-
  def get_mapping_permissions(addr)
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        range, perms, offset, dev, inode, pathname = l.chomp.split(" ",6)
        base, max = range.split('-').map{|x| x.to_i(16)}
        return perms if addr >= base and addr <= max
      end
    end
    return ""
  end

  ## Helper method for retrieving stack range
  def get_stack_range
    get_mapping_by_name('[stack]')
  end

  ## Newer kernels (>3.4) will label a tid's stack
  def get_thread_stack(tid)
    get_mapping_by_name('[stack:#{tid}]')
  end

  ## Helper method for retrieving heap range
  def get_heap_range
    get_mapping_by_name('[heap]')
  end

  ## Parse procfs and create a hash containing
  ## a listing of each mapped shared object
  def self.shared_libraries(p)
    raise "pid is 0" if p.to_i == 0

    if @shared_objects
      @shared_objects.clear
    else
      @shared_objects = Hash.new
    end

    File.open("/proc/#{p}/maps") do |f|
      f.each_line do |l|
        if l =~ /[a-zA-Z0-9].so/# and l =~ /xp /
          lib = l.split(' ', 6)
          sa = l.split('-', 0)
          next if lib[5] =~ /vdso/
          lib = lib[5].strip
          lib.gsub!(/[\s\n]+/, "")
          @shared_objects.store(sa[0].to_i(16), lib)
        end
      end
    end
    @shared_objects
  end

  ## instance method for above
  ## returns a hash of the mapped
  ## shared libraries
  def shared_libraries
    self.shared_libraries(@pid)
  end

  ## Search a specific page for a value
  ## Should be used by most search methods
  def search_page(base, max, val, &block)
    loc = []
    if self.use_ptrace_for_search == true
      while base.to_i < max.to_i
        r = native.ptrace(Ptrace::PEEK_TEXT, @pid, base, 0)
        loc << base if r == val
        base += 4
        yield loc if block_given?
      end
    else
      sz = max.to_i - base.to_i
      d = File.new("/proc/#{pid}/mem")
      d.seek(base.to_i, IO::SEEK_SET)
      b = d.read(sz)
      i = 0
      while i < sz
        if val == b[i,4].unpack('L')
          loc << base.to_i + i
          yield(base.to_i + i) if block_given?
        end
        i += 4
      end
      d.close
    end

    loc
  end

  def search_mem_by_name(name, val, &block)
    loc = []
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        if l =~ /\[#{name}\]/
          s,e = l.split('-')
          e = e.split(' ').first
          s = s.to_i(16)
          e = e.to_i(16)
          sz = e - s
          max = s + sz
          loc << search_page(s, max, val, &block)
        end
      end
    end
    loc
  end

  ## Searches all pages with permissions matching perm
  ## e.g. r-x rwx rw-
  ## for val, and executes block when found
  def search_mem_by_permission(perm, val, &block)
    loc = []
    File.open("/proc/#{pid}/maps") do |f|
      f.each_line do |l|
        if l.split(' ')[1] =~ /#{perm}/
          s,e = l.split('-')
          e = e.split(' ').first
          s = s.to_i(16)
          e = e.to_i(16)
          sz = e - s
          max = s + sz
          loc << search_page(s, max, val, &block)
        end
      end
    end
    loc
  end

  ## Search the heap for a value, returns an array of matches
  def search_heap(val, &block)
    search_mem_by_name('heap', val, &block)
  end

  ## Search the stack for a value, returns an array of matches
  def search_stack(val, &block)
    search_mem_by_name('stack', val, &block)
  end

  ## Search all mapped regions for a value
  def search_process(val, &block)
    loc = []
    self.mapped
    @mapped_regions.each_pair do |k,v|
      next if k == 0 or v == 0
      max = k+v
      loc << search_page(k, max, val, &block)
    end
    loc
  end

  def continue
    on_continue
    native.ptrace(Ptrace::CONTINUE, @pid, 0, 0)
  end

  def detach
    on_detach

    ## If we are detaching then we need to
    ## uninstall any breakpoints we set
    uninstall_bps

    native.ptrace(Ptrace::DETACH, @pid, 0, 0)
  end

  def single_step
    on_single_step
    native.ptrace(Ptrace::STEP, @pid, 1, 0)
  end

  ## Adds a breakpoint to be installed
  ## ip: Address to set breakpoint on
  ## name: name of breakpoint
  ## callable: Proc to .call at breakpoint
  def breakpoint_set(ip, name="", callable=nil, &block)
    callable = block if not callable and block_given?
    @breakpoints.each_key {|k| return if k == ip }
    bp = Breakpoint.new(ip, callable, @pid, name, @native)
    @breakpoints[ip] = bp
  end

  ## Remove a breakpoint by ip
  def breakpoint_clear(ip)
    bp = @breakpoints[ip]
    return nil if bp.nil?
    bp.uninstall
  end

  ## loop for wait()
  ## times: the number of wait calls to make
  def loop(times=nil)
    if times.kind_of? Numeric
      times.times do
        self.wait
      end
    elsif times.nil?
      self.wait while not @exited
    end
  end

  ## TODO - define these as constants
  def wifsignaled(status)
    (((((status) & 0x7f) + 1) >> 1) > 0)
  end

  def wifexited(status)
    wtermsig(status) == 0
  end

  def wifstopped(status)
    (((status) & 0xff) == 0x7f)
  end

  def wstopsig(status)
    wexitstatus(status)
  end

  def wexitstatus(status)
    (((status) & 0xff00) >> 8)
  end

  def wtermsig(status)
    ((status) & 0x7f)
  end

  def wcoredump(status)
    ((status) & 0x80)
  end

  ## Writing a wait loop on Linux is difficult. There are
  ## a lot of corner cases to account for and much of it
  ## is poorly documented. This method handles signals and
  ## ptrace events, and then invokes Ruby callbacks to
  ## handle them. This is not complete yet, unfortunately.
  ## You can pass an optional PID to this method which is
  ## the only PID we will wait() on. If you have any interest
  ## in hacking on Rtrace to improve it then this is the
  ## one of the best places to get started
  def wait(p = -1)
    status = nil

    begin
      r, status = Process.waitpid2(p, Wait::WALL)
    rescue SystemCallError => e
      ## TODO: handle this better
      raise Exception, "Errno::ECHILD" if e.kind_of?(Errno::ECHILD)
      return
    end

    ## We only care about pid and thread ids
    return if r != @pid and @tids.include?(r) == false

    ## Ruby Status object gives us this
    ## via stopped?. We don't need the
    ## wifstopped macro anymore
    #wstop = #wifstopped(status)
    wstop = status.stopped?

    ## Ruby Status object gives us the
    ## signal so we don't need to use
    ## wstopsig macro anymore
    #@signal = wstopsig(status)
    if status.stopped?
      @signal = status.stopsig
    else
      @signal = status.termsig
    end

    status = status.to_i
    return r if r == -1

    if wifexited(status) == true and wexitstatus(status) == 0
      ## Don't exit if only a tid died
      @exited = true if r == @pid
      try_method :on_exit, wexitstatus(status), r
      #exit if r == @pid
      @tids.delete(r)
      return
    elsif wifexited(status) == true
      ## Don't exit if only a tid died
      @exited = true if r == @pid
      try_method :on_exit, wexitstatus(status), r
      @tids.delete(r)
      #exit if r == @pid
      return
    elsif wifsignaled(status) == true
      ## uncaught signal?
    end

    if wstop == true ## STOP
      try_method :on_stop
    else
      ## The process was not stopped
      ## due to a signal... It is possible
      ## that a thread died we weren't
      ## tracing...
    end

    ## Here we handle all signals and event codes.
    ## Most of these have event handlers associated
    ## with them, we invoke those via 'try_method'
    ## Some of them require thread specific operations
    ## such as segv or sigill where the process cannot
    ## continue. In those cases we override @pid with
    ## the offending tid and then restore it later.
    ppid = @pid
    @pid = r if r != nil and r > 0

    try_method :on_signal, @signal

    case @signal
    when Signal::SIGINT
      try_method :on_sigint
      self.continue
    when Signal::SIGSEGV
      try_method :on_segv
    when Signal::SIGILL
      try_method :on_illegal_instruction
    when Signal::SIGIOT
      try_method :on_iot_trap
      self.continue
    when Signal::SIGSYSTRAP
      try_method :on_syscall
    when Signal::SIGTRAP
      event_code = (status >> 8)
      try_method :on_sigtrap
      r = self.get_registers
      ip = get_ip(r)
      ip -= 1

      ## Let user defined breakpoint handlers run
      try_method :on_breakpoint if @breakpoints.has_key?(ip)

      case event_code
        ## TODO: should work the same way as CLONE
      when Ptrace::EventCodes::VFORK, Ptrace::EventCodes::FORK
        p = FFI::MemoryPointer.new(:int, 1)
        native.ptrace(Ptrace::GETEVENTMSG, @pid, 0, p.to_i)
        ## Fix up the PID in each breakpoint
        if (1..65535) === p.get_int32(0)
          @breakpoints.each_pair do |k,v|
            v.each do |b|
              b.bppid = p[:pid]
            end
          end

          ## detach will handle calling uninstall_bps
          self.detach

          @pid = p[:pid]
          try_method :on_fork_child, @pid
        end

      when Ptrace::EventCodes::CLONE
        ## Get the new TID
        tid = FFI::MemoryPointer.new(:int, 1)
        native.ptrace(Ptrace::GETEVENTMSG, @pid, 0, tid.to_i)
        tid = tid.get_int32(0).to_i
        @tids.push(tid)

        ## Tell the new TID to continue. We are automatically already
        ## tracing it. This is totally ghetto but ptrace might
        ## fail here so we need to call waitpid and try again...
        begin
          r = native.ptrace(Ptrace::CONTINUE, tid, 0, 0)
        rescue SystemCallError => e
          r = Process.waitpid2(tid, (Wait::WALL|Wait::NOHANG))
          r = native.ptrace(Ptrace::CONTINUE, tid, 0, 0)
        end

      when Ptrace::EventCodes::EXEC
        try_method :on_execve

      when Ptrace::EventCodes::VFORK_DONE
        try_method :on_vfork_done

      when Ptrace::EventCodes::EXIT
        @exited = true if r == @pid
        p = FFI::MemoryPointer.new(:int, 1)
        native.ptrace(Ptrace::GETEVENTMSG, @pid, 0, p.to_i)
        @exited = true if r == @pid
        try_method :on_exit, p.get_int32(0), r
        @tids.delete(r)
        ## This is the main PID dieing
        #exit if r == @pid

      when Ptrace::EventCodes::SECCOMP
        try_method :on_seccomp
      end

      ## We either handled our breakpoint
      ## or we handled an event code
      self.continue

    when Signal::SIGCHLD
      try_method :on_sigchild

    when Signal::SIGTERM
      try_method :on_sigterm

    when Signal::SIGCONT
      try_method :on_continue
      self.continue

    when Signal::SIGSTOP
      try_method :on_sigstop
      self.continue

    when Signal::SIGKILL
      try_method :on_kill
      self.continue

    when Signal::SIGABRT
      try_method :on_abort
      self.continue

    when Signal::SIGBUS
      try_method :on_sigbus
      self.continue

    when Signal::SIGWINCH, Signal::SIGHUP, Signal::SIGQUIT,
      Signal::SIGFPE, Signal::SIGUSR1, Signal::SIGUSR2, Signal::SIGPIPE, Signal::SIGALRM,
      Signal::SIGSTKFLT, Signal::SIGTSTP, Signal::SIGTTIN, Signal::SIGTTOU, Signal::SIGURG,
      Signal::SIGXCPU, Signal::SIGXFSZ, Signal::SIGVTALRM, Signal::SIGPROF, Signal::SIGIO,
      Signal::SIGPOLL, Signal::SIGPWR, Signal::SIGSYS, Signal::SIGUNUSED
      try_method :unhandled_signal, @signal
      self.continue
    else
      raise "You are missing a handler for signal (#{@signal})"
    end

    @pid = ppid

    return @signal
  end

  ## Here we need to do something about the bp
  ## we just hit. We have a block to execute.
  ## Remember if you implement this on your own
  ## make sure to call super, and also realize
  ## IP won't look correct until this runs
  def on_breakpoint
    r = get_registers
    ip = get_ip(r)
    ip -= 1

    ## Call the block associated with the breakpoint
    @breakpoints[ip].call(r, self)

    ## The block may have called breakpoint_clear
    del = true if !@breakpoints[ip].installed?

    ## Uninstall and single step the bp
    @breakpoints[ip].uninstall
    r.eip = ip if @bits == 32
    r.rip = ip if @bits == 64
    set_registers(r)
    single_step

    if del == true
      ## The breakpoint block may have called breakpoint_clear
      @breakpoints.delete(ip)
    else
      @breakpoints[ip].install
    end
  end

  def on_attach()              end
  def on_detach()              end
  def on_single_step()         end
  def on_syscall_continue()    end
  def on_continue()            end
  def on_exit(exit_code, pid)  end
  def on_signal(signal)        end
  def on_sigint()              end
  def on_segv()                end
  def on_illegal_instruction() end
  def on_sigtrap()             end
  def on_fork_child(pid)       end
  def on_sigchild()            end
  def on_sigterm()             end
  def on_sigstop()             end
  def on_iot_trap()            end
  def on_stop()                end
  def on_execve()              end
  def on_vfork_done()          end
  def on_seccomp()             end
  def on_kill()                end
  def on_abort()               end
  def on_sigbus()              end
  def unhandled_signal(signal) end

  def on_syscall
    syscall_block.call get_registers, self
  end

  def get_registers
    return get_registers_32 if @bits == 32
    return get_registers_64 if @bits == 64
  end

  def print_registers
    return print_registers_32 if @bits == 32
    return print_registers_64 if @bits == 64
  end

  def get_machine_word
    return 4 if @bits == 32
    return 8 if @bits == 64
  end

  def get_ip(r)
    return r.eip if @bits == 32
    return r.rip if @bits == 64
  end

  def get_sp(r)
    return r.esp if @bits == 32
    return r.rsp if @bits == 64
  end

  def get_registers_32
    regs = FFI::MemoryPointer.new(PTRegs32, 1)
    native.ptrace(Ptrace::GETREGS, @pid, 0, regs.address)
    return PTRegs32.new regs
  end

  def get_registers_64
    regs = FFI::MemoryPointer.new(PTRegs64, 1)
    native.ptrace(Ptrace::GETREGS, @pid, 0, regs.address)
    return PTRegs64.new regs
  end

  def set_registers(regs)
    native.ptrace(Ptrace::SETREGS, @pid, 0, regs.to_ptr.address)
  end

  def print_registers_32
    regs = get_registers_32
    r = "eip 0x%08x\n" % regs.eip
    r += "ebp 0x%08x\n" % regs.ebp
    r += "esi 0x%08x\n" % regs.esi
    r += "edi 0x%08x\n" % regs.edi
    r += "esp 0x%08x\n" % regs.esp
    r += "eax 0x%08x\n" % regs.eax
    r += "ebx 0x%08x\n" % regs.ebx
    r += "ecx 0x%08x\n" % regs.ecx
    r += "edx 0x%08x" % regs.edx
  end

  def print_registers_64
    regs = get_registers_64
    r = "rip 0x%16x\n" % regs.rip
    r += "rbp 0x%16x\n" % regs.rbp
    r += "rsi 0x%16x\n" % regs.rsi
    r += "rdi 0x%16x\n" % regs.rdi
    r += "rsp 0x%16x\n" % regs.rsp
    r += "rax 0x%16x\n" % regs.rax
    r += "rbx 0x%16x\n" % regs.rbx
    r += "rcx 0x%16x\n" % regs.rcx
    r += "rdx 0x%16x\n" % regs.rdx
    r += "r8 0x%16x\n" % regs.r8
    r += "r9 0x%16x\n" % regs.r9
    r += "r10 0x%16x\n" % regs.r10
    r += "r11 0x%16x\n" % regs.r11
    r += "r12 0x%16x\n" % regs.r12
    r += "r13 0x%16x\n" % regs.r13
    r += "r14 0x%16x\n" % regs.r14
    r += "r15 0x%16x" % regs.r15
  end

  ## Read process memory using procfs
  def read_procfs(off, sz=4096)
    p = File.open("/proc/#{pid}/mem", "r")
    p.seek(off)
    r = p.read(sz)
    p.close
    return r
  end

  ## Write to process memory using procfs
  def write_procfs(off, data)
    p = File.open("/proc/#{pid}/mem", "w+")
    p.seek(off)
    r = p.write(data)
    p.close
    return r
  end

  ## Read process memory using ptrace
  def read(off, sz=4096)
    a = []
    max = off+sz
    while off < max
      a.push(native.ptrace(Ptrace::PEEK_TEXT, @pid, off, 0))
      return a.pack('L*') if a.last == -1 and FFI.errno != 0
      off+=4
    end
    a.pack('L*')
  end

  ## Write process memory using ptrace
  def write(off, data)
    while off < data.size
      native.ptrace(Ptrace::POKE_TEXT, @pid, off, data[off,4].unpack('L').first)
      off += 4
    end
  end

  def read64(off); read(off, 8).unpack("Q").first; end
  def read32(off); read(off, 4).unpack("L").first; end
  def read16(off); read(off, 2).unpack("v").first; end
  def read8(off); read(off, 1)[0]; end
  def write64(off, v); write(off, [v].pack("Q")); end
  def write32(off, v); write(off, [v].pack("L")); end
  def write16(off, v); write(off, [v].pack("v")); end
  def write8(off, v); write(off, v.chr); end
end
