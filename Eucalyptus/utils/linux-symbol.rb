## Copyright 2015,2016, Yahoo! Inc.
## Copyrights licensed under the New BSD License. See the
## accompanying LICENSE file in the project root folder for terms.

## Simple script that uses nm to search for symbol offsets
## This is mainly for validating the parse_elf code
## ruby linux-symbol.rb /usr/local/my_binary 'authenticate'

if !ARGV[0] or !ARGV[1]
	puts "I need a file and a symbol!"
	exit
end

elf_obj = ARGV[0].to_s
symbol = ARGV[1].to_s

`/usr/bin/nm -C -D #{elf_obj}`.each_line do |l|
    address, t, func_sig = l.split(' ', 3)

    if address.match(/^\h+$/i) and address.size.between?(8,16) == true
        func_sig = func_sig.split('(').first if func_sig =~ /\(/
        puts "bp=0x#{address}, name=#{func_sig.chomp}, lib=#{elf_obj}" if func_sig =~ /#{symbol}/i
    end
end
