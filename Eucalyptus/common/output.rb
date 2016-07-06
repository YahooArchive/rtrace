## Copyright 2015,2016, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the accompanying LICENSE file in the project root folder for terms.

class EucalyptusLog
    def initialize(out)
        @out = out
    end

    def str(s)
        @out.puts s
    end

    def hit(addr, function_name)
        @out.puts "[ #{addr} #{function_name} ]"
    end

    def finalize
        @out.puts "...Eucalyptus is done!"
    end
end