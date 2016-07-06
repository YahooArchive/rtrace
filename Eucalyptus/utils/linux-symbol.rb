## Copyright 2015,2016, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Simple script that uses nm to search for symbol offsets
## This is mainly for validating the parse_elf code
## ruby linux-symbol.rb /usr/local/my_binary 'authenticate'

if ARGV.size < 2
	STDERR.puts "#{$0} <file> <symbol>"
	exit
end

elf_obj = ARGV[0].to_s
symbol = ARGV[1].to_s

cmd = ["nm", "-C", "-D", elf_obj]
IO.popen({"LC_ALL" => "C"}, cmd) do |io|
  io.each_line do |line|
    address, _, func_sig = line.split(' ', 3)

    if address.match(/^\h+$/i) and address.size.between?(8,16) == true
        func_sig = func_sig.split('(').first if func_sig =~ /\(/
        if func_sig =~ /#{symbol}/i
          puts "bp=0x#{address}, name=#{func_sig.chomp}, lib=#{elf_obj}"
        end
    end
  end
end