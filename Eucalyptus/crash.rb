## Copyright 2015, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Crash is a partial MSEC (!exploitable) WinDbg extension
## reimplementation which uses the Rtrace debugging library.
##
## Usage:
##
## Catch a debug event like segfault or illegal instruction
## then pass your rtrace instance to this class:
##
## Crash.new(@rtrace).exploitable?
##
## Thats it! The class will use your rtrace instance to
## determine the state of the process. This is done examining
## the last signal or debug event the process received and
## the register states.

## This code is far from complete. It needs a lot of work...

require 'rtrace'

class Crash
    EXPLOITABLE = 1
    POSSIBLY_EXPLOITABLE = 2
    NOT_EXPLOITABLE = 3
    UNKNOWN = 4

    attr_accessor :state, :status, :rtrace

    ## TOOD: make status a bitmask so we can report
    ## on several things at once
    def initialize(rw)
        @rtrace = rw
        status = UNKNOWN

        r = @rtrace.get_registers

        if @rtrace.bits == 32
            status = reg_check(r.eip)
            status = reg_check(r.ebp)
        else
            status = reg_check(r.rip)
            status = reg_check(r.rbp)
        end

        case @rtrace.signal
            when Signal::SIGILL
                puts "Illegal instruction indicates attacker controlled code flow - EXPLOITABLE"
                status = EXPLOITABLE
            when Signal::SIGIOT
                puts "IOT Trap may indicate an exploitable crash (stack cookie?) - POSSIBLY EXPLOITABLE"
                status = POSSIBLY_EXPLOITABLE
            when Signal::SIGSEGV
                puts "A segmentation fault may be exploitable, needs further analysis - POSSIBLY EXPLOITABLE"
                status = POSSIBLY_EXPLOITABLE
        end
    end

    ## Crash.exploitable?
    ## Who needs !exploitable when you've got exploitable?
    def exploitable?
        return true if status == EXPLOITABLE or status == POSSIBLY_EXPLOITABLE
        return false
    end

    def get_stack_trace
        ## TODO: Not implemented yet
    end

    def reg_check(reg)
        stack_range = @rtrace.get_stack_range
        heap_range = @rtrace.get_heap_range

        stack_range.each do |s|
            if reg == s.first..s.last
              puts "Executing instructions from the stack - EXPLOITABLE"
              return EXPLOITABLE
            end
        end

        heap_range.each do |h|
            if reg == h.first..h.last
              puts "Executing instructions from the heap - EXPLOITABLE"
              return EXPLOITABLE
            end
        end

        case reg
            when 0x41414141
                puts "Register is controllable AAAA... - EXPLOITABLE"
                return EXPLOITABLE
            when 0x0..0x1000
                puts "NULL Pointer dereference - NOT EXPLOITABLE (unless you control the offset from NULL)"
                return NOT_EXPLOITABLE
        end
    end
end
