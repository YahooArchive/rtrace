require 'parse_elf'
require 'pp'

d = ELFReader.new(ARGV[0])

d.phdr.each do |p|
  puts sprintf("\n%s", d.get_phdr_name(p))
  pp p
end

## The section headers (if any) are automatically
## parsed at object instantiation
d.shdr.each do |s|
  puts sprintf("\n%s", d.get_shdr_by_name(s))
  pp s
end

## The dynamic segment is automatically
## parsed at object instantiation
d.dyn.each do |dyn|
  pp dyn
end

d.parse_reloc do |r|
  sym = d.lookup_rel(r)
  puts sprintf("RELOC: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_dyn_symbol_name(sym));
end

d.parse_dynsym
d.parse_symtab

d.dynsym_symbols.each do |sym|
  puts sym.st_value.to_s(16) if d.get_symbol_type(sym) == SymbolTypes::STT_FUNC and d.get_dyn_symbol_name(sym) == "malloc"
end

d.symtab_symbols.each do |sym|
  puts sym.st_value.to_s(16) if d.get_symbol_type(sym) == SymbolTypes::STT_FUNC and d.get_sym_symbol_name(sym) == "malloc"
end
