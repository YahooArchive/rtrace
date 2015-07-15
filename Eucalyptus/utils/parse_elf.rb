## Optional ELF parser for Rtrace/Eucalyptus
## Support (and testing) for x86, x86_64 and ARM
## This is *NOT* a robust ELF parser. It was
## written specifically for extracting symbols
## from gcc/clang generated ELFs whose structures
## have not been tampered with. It does however
## use the ELF program header for parsing so
## it should work on a sstripped ELF. Pull
## requests for improving it are welcome!

## TODO: parse rela.dyn

require 'bindata'

## Basic ELF Header
class ELF32Header < BinData::Record
  endian :little
  string :e_ident, :read_length => 16
  uint16 :e_type
  uint16 :e_machine
  uint32 :e_version
  uint32 :e_entry
  uint32 :e_phoff
  uint32 :e_shoff
  uint32 :e_flags
  uint16 :e_ehsize
  uint16 :e_phentsize
  uint16 :e_phnum
  uint16 :e_shentsize
  uint16 :e_shnum
  uint16 :e_shstrndx
end

## ELF Program Header
class ELF32ProgramHeader < BinData::Record
  endian :little
  uint32 :p_type
  uint32 :p_offset
  uint32 :p_vaddr
  uint32 :p_paddr
  uint32 :p_filesz
  uint32 :p_memsz
  uint32 :p_flags
  uint32 :p_align
end

## ELF Section Header
class ELF32SectionHeader < BinData::Record
  endian :little
  uint32 :sh_name
  uint32 :sh_type
  uint32 :sh_flags
  uint32 :sh_addr
  uint32 :sh_offset
  uint32 :sh_size
  uint32 :sh_link
  uint32 :sh_info
  uint32 :sh_addralign
  uint32 :sh_entsize
end

class ELF32Dynamic < BinData::Record
  endian :little
  uint32 :d_tag
  uint32 :d_val
  #uint32 :d_ptr
end

class ELF32Symbol < BinData::Record
  endian :little
  uint32 :st_name   ## Symbol name (string tbl index)
  uint32 :st_value  ## Symbol value
  uint32 :st_size   ## Symbol size
  uint8  :st_info   ## Symbol type and binding
  uint8  :st_other  ## Symbol visibility
  uint16 :st_shndx  ## Section index
end

class ELF32Relocation < BinData::Record
  endian :little
  uint32 :r_offset  ## Address
  uint32 :r_info    ## Type
end

## Basic ELF Header
class ELF64Header < BinData::Record
  endian :little
  string :e_ident, :read_length => 16
  uint16 :e_type
  uint16 :e_machine
  uint32 :e_version
  uint64 :e_entry
  uint64 :e_phoff
  uint64 :e_shoff
  uint32 :e_flags
  uint16 :e_ehsize
  uint16 :e_phentsize
  uint16 :e_phnum
  uint16 :e_shentsize
  uint16 :e_shnum
  uint16 :e_shstrndx
end

## ELF Program Header
class ELF64ProgramHeader < BinData::Record
  endian :little
  uint32 :p_type
  uint32 :p_flags
  uint64 :p_offset
  uint64 :p_vaddr
  uint64 :p_paddr
  uint32 :p_filesz
  uint32 :p_memsz
  uint32 :p_align
end

## ELF Section Header
class ELF64SectionHeader < BinData::Record
  endian :little
  uint32 :sh_name
  uint32 :sh_type
  uint64 :sh_flags
  uint64 :sh_addr
  uint64 :sh_offset
  uint64 :sh_size
  uint32 :sh_link
  uint32 :sh_info
  uint64 :sh_addralign
  uint64 :sh_entsize
end

class ELF64Dynamic < BinData::Record
  endian :little
  uint64 :d_tag
  uint64 :d_val
  #uint32 :d_ptr
end

class ELF64Symbol < BinData::Record
  endian :little
  uint32 :st_name   ## Symbol name (string tbl index)
  uint8  :st_info   ## Symbol type and binding
  uint8  :st_other  ## Symbol visibility
  uint16 :st_shndx  ## Section index
  uint64 :st_value  ## Symbol value
  uint64 :st_size   ## Symbol size
end

class ELF64Relocation < BinData::Record
  endian :little
  uint64 :r_offset  ## Address
  uint64 :r_info    ## Type
end

class ELFTypes
  ET_NONE = 0         ## No file type
  ET_REL = 1          ## Relocatable file
  ET_EXEC = 2         ## Executable file
  ET_DYN = 3          ## Shared object file
  ET_CORE = 4         ## Core file
end

class ShdrTypes
  SHT_NULL     = 0 ## Section header table entry unused
  SHT_PROGBITS = 1 ## Program data
  SHT_SYMTAB  = 2  ## Symbol table
  SHT_STRTAB  = 3  ## String table
  SHT_RELA    = 4  ## Relocation entries with addends
  SHT_HASH    = 5  ## Symbol hash table
  SHT_DYNAMIC = 6  ## Dynamic linking information
  SHT_NOTE    = 7  ## Notes
  SHT_NOBITS  = 8  ## Program space with no data (bss)
  SHT_REL     = 9  ## Relocation entries, no addends
  SHT_SHLIB   = 10 ## Reserved
  SHT_DYNSYM  = 11 ## Dynamic linker symbol table
  SHT_INIT_ARRAY = 14 ## Array of constructors
  SHT_FINI_ARRAY = 15 ## Array of destructors
  SHT_PREINIT_ARRAY = 16  ## Array of pre-constructors
  SHT_GROUP = 17          ## Section group
  SHT_SYMTAB_SHNDX = 18   ## Extended section indexes
  SHT_NUM = 19            ## Number of defined types.
  SHT_LOOS =  0x60000000          ## Start OS-specific.
  SHT_GNU_HASH = 0x6ffffff6       ## GNU-style hash table.
  SHT_GNU_LIBLIST = 0x6ffffff7    ## Prelink library list
  SHT_CHECKSUM = 0x6ffffff8       ## Checksum for DSO content.
  SHT_LOSUNW = 0x6ffffffa         ## Sun-specific low bound.
  SHT_SUNW_move = 0x6ffffffa
  SHT_SUNW_COMDAT = 0x6ffffffb
  SHT_SUNW_syminfo = 0x6ffffffc
  SHT_GNU_verdef = 0x6ffffffd     ## Version definition section.
  SHT_GNU_verneed = 0x6ffffffe    ## Version needs section.
  SHT_GNU_versym = 0x6fffffff     ## Version symbol table.
  SHT_HISUNW = 0x6fffffff         ## Sun-specific high bound.
  SHT_HIOS = 0x6fffffff      ## End OS-specific type
  SHT_LOPROC = 0x70000000    ## Start of processor-specific
  SHT_HIPROC = 0x7fffffff    ## End of processor-specific
  SHT_LOUSER = 0x80000000    ## Start of application-specific
  SHT_HIUSER = 0x8fffffff    ## End of application-specific
end

class PhdrTypes
  PT_NULL = 0     ## Program header table entry unused
  PT_LOAD = 1     ## Loadable program segment
  PT_DYNAMIC = 2  ## Dynamic linking information
  PT_INTERP = 3   ## Program interpreter
  PT_NOTE = 4     ## Auxiliary information
  PT_SHLIB = 5    ## Reserved
  PT_PHDR = 6     ## Entry for header table itself
  PT_TLS = 7      ## Thread-local storage segment
  PT_NUM = 8      ## Number of defined types
  PT_LOOS =  0x60000000  ## Start of OS-specific
  PT_GNU_EH_FRAME = 0x6474e550 ## GCC .eh_frame_hdr segment
  PT_GNU_STACK = 0x6474e551    ## Indicates stack executability
  PT_GNU_RELRO = 0x6474e552    ## Read-only after relocation
  PT_LOSUNW = 0x6ffffffa
  PT_SUNWSTACK = 0x6ffffffb   ## Stack segment
  PT_HIOS  = 0x6fffffff       ## End of OS-specific
  PT_LOPROC = 0x70000000      ## Start of processor-specific
  PT_HIPROC = 0x7fffffff      ## End of processor-specific
end

class DynamicTypes
  DT_NULL     = 0       ## Marks end of dynamic section
  DT_NEEDED   = 1       ## Name of needed library
  DT_PLTRELSZ = 2       ## Size in uint8s of PLT relocs
  DT_PLTGOT   = 3       ## Processor defined value
  DT_HASH     = 4       ## Address of symbol hash table
  DT_STRTAB   = 5       ## Address of string table
  DT_SYMTAB   = 6       ## Address of symbol table
  DT_RELA     = 7       ## Address of Rela relocs
  DT_RELASZ   = 8       ## Total size of Rela relocs
  DT_RELAENT  = 9       ## Size of one Rela reloc
  DT_STRSZ    = 10      ## Size of string table
  DT_SYMENT   = 11      ## Size of one symbol table entry
  DT_INIT     = 12      ## Address of init function
  DT_FINI     = 13      ## Address of termination function
  DT_SONAME   = 14      ## Name of shared object
  DT_RPATH    = 15      ## Library search path (deprecated)
  DT_SYMBOLIC = 16      ## Start symbol search here
  DT_REL      = 17      ## Address of Rel relocs
  DT_RELSZ    = 18      ## Total size of Rel relocs
  DT_RELENT   = 19      ## Size of one Rel reloc
  DT_PLTREL   = 20      ## Type of reloc in PLT
  DT_DEBUG    = 21      ## For debugging; unspecified
  DT_TEXTREL  = 22      ## Reloc might modify .text
  DT_JMPREL   = 23      ## Address of PLT relocs
  DT_BIND_NOW = 24      ## Process relocations of object
  DT_INIT_ARRAY   = 25  ## Array with addresses of init fct
  DT_FINI_ARRAY   = 26  ## Array with addresses of fini fct
  DT_INIT_ARRAYSZ = 27  ## Size in uint8s of DT_INIT_ARRAY
  DT_FINI_ARRAYSZ = 28  ## Size in uint8s of DT_FINI_ARRAY
  DT_RUNPATH  = 29      ## Library search path
  DT_FLAGS    = 30      ## Flags for the object being loaded
  DT_ENCODING = 32      ## Start of encoded range
  DT_PREINIT_ARRAY    = 32     ## Array with addresses of preinit fct
  DT_PREINIT_ARRAYSZ  = 33     ## size in uint8s of DT_PREINIT_ARRAY
  DT_NUM  = 34      ## Number used
  DT_LOOS = 0x6000000d    ## Start of OS-specific
  DT_HIOS = 0x6ffff000    ## End of OS-specific
  DT_LOPROC = 0x70000000  ## Start of processor-specific
  DT_HIPROC = 0x7fffffff  ## End of processor-specific
  DT_ADDRRNGLO    = 0x6ffffe00
  DT_GNU_HASH     = 0x6ffffef5  ## GNU-style hash table.
  DT_TLSDESC_PLT  = 0x6ffffef6
  DT_TLSDESC_GOT  = 0x6ffffef7
  DT_GNU_CONFLICT = 0x6ffffef8  ## Start of conflict section
  DT_GNU_LIBLIST  = 0x6ffffef9  ## Library list
  DT_CONFIG   = 0x6ffffefa  ## Configuration information.
  DT_DEPAUDIT = 0x6ffffefb  ## Dependency auditing.
  DT_AUDIT    = 0x6ffffefc  ## Object auditing.
  DT_PLTPAD   = 0x6ffffefd  ## PLT padding.
  DT_MOVETAB  = 0x6ffffefe  ## Move table.
  DT_SYMINFO  = 0x6ffffeff  ## Syminfo table.
  DT_ADDRRNGHI = 0x6ffffeff
end

class SymbolBind
  STB_LOCAL   = 0       ## Local symbol
  STB_GLOBAL  = 1       ## Global symbol
  STB_WEAK    = 2       ## Weak symbol
  STB_NUM     = 3       ## Number of defined types.
  STB_LOOS    = 10      ## Start of OS-specific
  STB_HIOS    = 12      ## End of OS-specific
  STB_LOPROC  = 13      ## Start of processor-specific
  STB_HIPROC  = 15      ## End of processor-specific
end

class SymbolTypes
  STT_NOTYPE  = 0       ## Symbol type is unspecified
  STT_OBJECT  = 1       ## Symbol is a data object
  STT_FUNC    = 2       ## Symbol is a code object
  STT_SECTION = 3       ## Symbol associated with a section
  STT_FILE    = 4       ## Symbol's name is file name
  STT_COMMON  = 5       ## Symbol is a common data object
  STT_TLS     = 6       ## Symbol is thread-local data object
  STT_NUM     = 7       ## Number of defined types.
  STT_LOOS    = 10      ## Start of OS-specific
  STT_HIOS    = 12      ## End of OS-specific
  STT_LOPROC  = 13      ## Start of processor-specific
  STT_HIPROC  = 15      ## End of processor-specific
end

class EIClass
  EI_CLASS	 = 4
  ELFCLASS32   = 1
  ELFCLASS64   = 2
end

## Members:
##
##  ehdr - a structure holding the ELF header
##  phdr - an array of BinData structures holding each Program header
##  shdr - an array of BinData structures holding each Section header
##  dyn  - an array of BinData structures holding each dynamic table entry
##  symbols - an array of BinData structures holding each symbol table entry
##
## Methods:
##
##  parse_ehdr - stores the Elf header in the ELFReader::ehdr BinData structure
##  parse_phdr - stores an array of BinData structures containing the Phdr in ELFReader::phdr
##  parse_shdr - stores an array of BinData structures containing the Shdr in ELFReader::shdr
##  parse_dyn  - stores an array of BinData structures containing the Dynamic table in ELFReader::dyn
##  parse_dynsym - stores an array of BinData structures containing the Dyn in ELFReader::dyn
##  parse_symtab - returns an array of BinData structures containing the symbol table
class ELFReader
  attr_accessor :opts, :elf, :ehdr, :phdr, :shdr, :dyn, :strtab, :hash,
    :jmprel, :rel, :dynsym, :symtab, :syment, :dynsym_symbols,
    :symtab_symbols, :reloc,  :gnu_hash, :bits, :baseaddr,
    :dynsym_sym_count

  def initialize(elf_file)
    begin
      @elf = File.open(elf_file, 'rb').read
      @bits = 32
      if @elf[EIClass::EI_CLASS].unpack('c').first == EIClass::ELFCLASS32
        @bits = 32
        @baseaddr = 0x8048000
      end

      if @elf[EIClass::EI_CLASS].unpack('c').first == EIClass::ELFCLASS64
        @bits = 64
        @baseaddr = 0x400000
      end

    rescue Exception => e
      puts "Could not read [#{elf_file}] (#{e})"
      exit
    end

    @phdr = []
    @shdr = []
    @dyn  = []
    @reloc  = []
    @dynsym_symbols = []
    @symtab_symbols = []

    @dynsym_sym_count = 0
    @symtab_sym_count = 0

    parse_ehdr
    parse_phdr
    parse_shdr
    parse_dyn
  end

  def parse_ehdr
    @ehdr = ELF32Header.new if @bits == 32
    @ehdr = ELF64Header.new if @bits == 64
    @ehdr.read(@elf.dup)
  end

  def parse_phdr
    0.upto(ehdr.e_phnum.to_i-1) do |j|
      p = ELF32ProgramHeader.new if @bits == 32
      p = ELF64ProgramHeader.new if @bits == 64
      p.read(@elf.dup[ehdr.e_phoff.to_i + (ehdr.e_phentsize.to_i * j), ehdr.e_phentsize.to_i])
      phdr.push(p)
    end
  end

  def get_phdr(type)
    phdr.each do |p|
      return p if p.p_type.to_i == type
    end
    return nil
  end

  def get_phdr_name(phdr)
    case phdr.p_type.to_i
    when PhdrTypes::PT_NULL
      return "PT_NULL"
    when PhdrTypes::PT_LOAD
      return "PT_LOAD"
    when PhdrTypes::PT_DYNAMIC
      return "PT_DYNAMIC"
    when PhdrTypes::PT_INTERP
      return "PT_INTERP"
    when PhdrTypes::PT_NOTE
      return "PT_NOTE"
    when PhdrTypes::PT_SHLIB
      return "PT_SHLIB"
    when PhdrTypes::PT_PHDR
      return "PT_PHDR"
    when PhdrTypes::PT_TLS
      return "PT_TLS"
    when PhdrTypes::PT_NUM
      return "PT_NUM"
    when PhdrTypes::PT_LOOS
      return "PT_LOOS"
    when PhdrTypes::PT_GNU_EH_FRAME
      return "PT_GNU_EH_FRAME"
    when PhdrTypes::PT_GNU_STACK
      return "PT_GNU_STACK"
    when PhdrTypes::PT_GNU_RELRO
      return "PT_GNU_RELRO"
    when PhdrTypes::PT_LOSUNW
      return "PT_LOSUNW"
    when PhdrTypes::PT_SUNWSTACK
      return "PT_SUNWSTACK"
    when PhdrTypes::PT_HIOS
      return "PT_HIOS"
    when PhdrTypes::PT_LOPROC
      return "PT_LOPROC"
    when PhdrTypes::PT_HIPROC
      return "PT_HIPROC"
    end
  end

  def parse_shdr
    0.upto(@ehdr.e_shnum.to_i-1) do |j|
      s = ELF32SectionHeader.new if @bits == 32
      s = ELF64SectionHeader.new if @bits == 64
      s.read(@elf.dup[@ehdr.e_shoff + (@ehdr.e_shentsize * j), @ehdr.e_shentsize])
      @shstrtab = s if s.sh_type.to_i == ShdrTypes::SHT_STRTAB and j == @ehdr.e_shstrndx.to_i
      shdr.push(s)
    end
  end

  def get_shdr(type)
    shdr.each do |s|
      return s if s.sh_type.to_i == type
    end
    return nil
  end

  def get_shdr_by_name(shdr)
    parse_dyn if dyn.size == 0
    return if @shstrtab.nil? or shdr.sh_type == 0
    str = @elf.dup[@shstrtab.sh_offset.to_i + shdr.sh_name.to_i, 256]
    str = str[0, str.index("\x00")]
  end

  def parse_dyn
    p = get_phdr(PhdrTypes::PT_DYNAMIC)
    return if not p
    dynamic_section_offset = p.p_vaddr.to_i

    if @bits == 32
      d = ELF32Dynamic.new
      @strtab = ELF32SectionHeader.new
      @hash = ELF32SectionHeader.new
      @gnu_hash = ELF32SectionHeader.new
      @dynsym = ELF32SectionHeader.new
      @jmprel = ELF32SectionHeader.new
      @rel = ELF32SectionHeader.new
    elsif @bits == 64
      d = ELF64Dynamic.new
      @strtab = ELF64SectionHeader.new
      @hash = ELF64SectionHeader.new
      @gnu_hash = ELF64SectionHeader.new
      @dynsym = ELF64SectionHeader.new
      @jmprel = ELF64SectionHeader.new
      @rel = ELF64SectionHeader.new
    end

    @syment = 0
    @pltrelsz = 0
    @relsz = 0

    0.upto(p.p_filesz.to_i / d.num_bytes.to_i) do |j|
      d = ELF32Dynamic.new if @bits == 32
      d = ELF64Dynamic.new if @bits == 64
      d.read(@elf.dup[p.p_offset.to_i + (d.num_bytes.to_i * j), d.num_bytes.to_i])

      break if d.d_tag.to_i == DynamicTypes::DT_NULL

      exec_type = 1 if ehdr.e_type.to_i == ELFTypes::ET_EXEC
      dyna_type = 1 if ehdr.e_type.to_i == ELFTypes::ET_DYN

      case d.d_tag.to_i
      when DynamicTypes::DT_STRTAB
        @strtab.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @strtab.sh_offset = d.d_val.to_i if dyna_type
      when DynamicTypes::DT_SYMENT
        @syment = d.d_val.to_i
      when DynamicTypes::DT_HASH
        @hash.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @hash.sh_offset = d.d_val.to_i if dyna_type
        @dynsym_sym_count = @elf.dup[hash.sh_offset + 4, 4].unpack('V')[0]
      when DynamicTypes::DT_GNU_HASH
        @gnu_hash.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @gnu_hash.sh_offset = d.d_val.to_i if dyna_type
        ## DT_HASH usually trumps DT_GNU_HASH
        @dynsym_sym_count = parse_dt_gnu_hash if @dynsym_sym_count == 0 and @hash.sh_offset == 0
      when DynamicTypes::DT_SYMTAB
        @dynsym.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @dynsym.sh_offset = d.d_val.to_i if dyna_type
      when DynamicTypes::DT_PLTRELSZ
        @pltrelsz = d.d_val.to_i
      when DynamicTypes::DT_RELSZ
        @relsz = d.d_val.to_i
      when DynamicTypes::DT_JMPREL
        @jmprel.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @jmprel.sh_offset = d.d_val.to_i if dyna_type
      when DynamicTypes::DT_REL
        @rel.sh_offset = d.d_val.to_i - @baseaddr if exec_type
        @rel.sh_offset = d.d_val.to_i if dyna_type
      end

      dyn.push(d)
    end
  end

  ## Returns the number of symbols
  ## DT_GNU_HASH is poorly documented. "Read the source"
  ## is not an appropriate response. Thanks Metasm
  ## for providing a reference implementation
  def parse_dt_gnu_hash
    hbl = @elf.dup[@gnu_hash.sh_offset, 4].unpack('V')[0]
    si = @elf.dup[@gnu_hash.sh_offset+4, 4].unpack('V')[0]
    mw = @elf.dup[@gnu_hash.sh_offset+8, 4].unpack('V')[0]
    shift2 = @elf.dup[@gnu_hash.sh_offset+12, 4].unpack('V')[0]
    filter = []
    hbu = []

    xword = 4
    xword = 8 if bits == 64

    mw.times do |i|
      filter.push(@elf.dup[@gnu_hash.sh_offset+16+i, xword].unpack('V')[0])
    end

    hbl.times do |i|
      hbu.push(@elf.dup[@gnu_hash.sh_offset+(mw*xword)+i, xword].unpack('V')[0])
    end

    hs = 0

    hbu.each do |hb|
      i = 0
      next if hb == 0
      loop do
        f = @elf.dup[@gnu_hash.sh_offset+(mw*xword)+(hbl*4)+i, 4].unpack('V')[0]
        i+=4
        hs += 1
        break if f & 1 == 1
      end
    end

    return hs + si
  end

  ## Unused method
  def get_dyn(type)
    dyn.each do |d|
      if d.d_tag.to_i == type
        return d
      end
    end
  end

  def parse_reloc(&block)
    parse_rel(@rel, @relsz, &block)
    parse_rel(@jmprel, @pltrelsz, &block)
  end

  def parse_rel(rel_loc, sz)
    p = get_phdr(PhdrTypes::PT_DYNAMIC)
    if p.nil? == false
      #parse the dynamic relocations
      tr = ELF32Relocation.new if @bits == 32
      tr = ELF64Relocation.new if @bits == 64

      0.upto((sz.to_i-1) / tr.num_bytes) do |j|
        r = ELF32Relocation.new if @bits == 32
        r = ELF64Relocation.new if @bits == 64

        r.read(@elf.dup[rel_loc.sh_offset.to_i + j*tr.num_bytes, tr.num_bytes])
        # TODO: merge with existing symbols? symbols.push(lookup_rel(r))
        # parse_reloc should be stand alone

        #s is a temporary ElfSymbol
        #check to see if it already exists by name
        s = lookup_rel(r)
        sym = get_symbol_by_name(get_dyn_symbol_name(s))

        #if the symbol already exists, and it doesnt have an address
        # set the relocation info to point to the plt address
        if not sym
          @dynsym_symbols.push(s)
        else
          sym.st_value = s.st_value if 0 == sym.st_value.to_i
        end

        yield(r) if block_given?

        reloc.push(r)
      end
    else
      puts "[-] No PT_DYNAMIC phdr entry. (static binary)"
    end
  end

  def lookup_rel(r)
    addr = r.r_offset

    if @bits == 32
      r_type = r.r_info & 0xff
      pos = r.r_info >> 8
      sym = ELF32Symbol.new
    else
      r_type = r.r_info & 0xffffffff
      pos = r.r_info >> 32
      sym = ELF64Symbol.new
    end

    sym.read(@elf.dup[dynsym.sh_offset + (pos * sym.num_bytes), sym.num_bytes])

    sym.st_value = addr if sym.st_value.to_i == 0
    return sym
  end

  def parse_dynsym
    d = get_shdr(ShdrTypes::SHT_DYNSYM)

    return if !d.kind_of? ELF32SectionHeader and !d.kind_of? ELF64SectionHeader

    0.upto(@dynsym_sym_count.to_i-1) do |j|
      sym = ELF32Symbol.new if @bits == 32
      sym = ELF64Symbol.new if @bits == 64
      sym.read(@elf.dup[d.sh_offset.to_i + (j * sym.num_bytes), sym.num_bytes])
      str = @elf.dup[strtab.sh_offset.to_i + sym.st_name.to_i, 256]

      yield(sym) if block_given?

      @dynsym_symbols.push(sym)
    end
  end

  def parse_symtab
    @symtab = get_shdr(ShdrTypes::SHT_SYMTAB)

    return if !@symtab.kind_of? ELF32SectionHeader and !@symtab.kind_of? ELF64SectionHeader

    @sym_str_tbl = shdr[@symtab.sh_link.to_i]

    @symtab_sym_count = (@symtab.sh_size.to_i / (ELF32Symbol.new).num_bytes) if @bits == 32
    @symtab_sym_count = (@symtab.sh_size.to_i / (ELF64Symbol.new).num_bytes) if @bits == 64

    0.upto(@symtab_sym_count.to_i-1) do |j|
      sym = ELF32Symbol.new if @bits == 32
      sym = ELF64Symbol.new if @bits == 64
      sym.read(@elf.dup[@symtab.sh_offset.to_i + (j * sym.num_bytes), sym.num_bytes])
      str = @elf.dup[@sym_str_tbl.sh_offset.to_i + sym.st_name.to_i, 256]

      yield(sym) if block_given?

      @symtab_symbols.push(sym)
    end
  end

  def get_symbol_by_name(name)
    @dynsym_symbols.each do |s|
      return s if get_dyn_symbol_name(s) == name
    end

    @symtab_symbols.each do |s|
      return s if get_sym_symbol_name(s) == name
    end

    return nil
  end

  def get_dyn_symbol_name(sym)
    str = @elf.dup[@strtab.sh_offset.to_i + sym.st_name.to_i, 256]
    str = str[0, str.index("\x00")]
  end

  def get_sym_symbol_name(sym)
    str = @elf.dup[@sym_str_tbl.sh_offset.to_i + sym.st_name.to_i, 256]
    str = str[0, str.index("\x00")]
  end

  def get_symbol_bind(sym)
    case (sym.st_info.to_i >> 4)
    when SymbolBind::STB_LOCAL
      return "LOCAL"
    when SymbolBind::STB_GLOBAL
      return "GLOBAL"
    when SymbolBind::STB_WEAK
      return "WEAK"
    when SymbolBind::STB_NUM
      return "NUM"
    when SymbolBind::STB_LOOS
      return "LOOS"
    when SymbolBind::STB_HIOS
      return "HIOS"
    when SymbolBind::STB_LOPROC
      return "LOPROC"
    when SymbolBind::STB_HIPROC
      return "HIPROC"
    end
  end

  def get_symbol_type(sym)
    case (sym.st_info.to_i & 0xf)
    when SymbolTypes::STT_NOTYPE
      return "NOTYPE"
    when SymbolTypes::STT_OBJECT
      return "OBJECT"
    when SymbolTypes::STT_FUNC
      return "FUNC"
    when SymbolTypes::STT_SECTION
      return "SECTION"
    when SymbolTypes::STT_FILE
      return "FILE"
    when SymbolTypes::STT_COMMON
      return "COMMON"
    when SymbolTypes::STT_TLS
      return "TLS"
    when SymbolTypes::STT_NUM
      return "NUM"
    when SymbolTypes::STT_LOOS
      return "LOOS"
    when SymbolTypes::STT_HIOS
      return "HIOS"
    when SymbolTypes::STT_LOPROC
      return "LOPROC"
    when SymbolTypes::STT_HIPROC
      return "HIPROC"
    end
  end

end

if $0 == __FILE__
  require 'pp'

  d = ELFReader.new(ARGV[0])

  ## The Elf header is automatically parsed
  ## at object instantiation
  pp d.ehdr

  ## The program headers are automatically
  ## parsed at object instantiation
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

  ## Parse the relocation entires for dynamic executables
  d.parse_reloc do |r|
    sym = d.lookup_rel(r)
    puts sprintf("RELOC: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_dyn_symbol_name(sym));
  end

  ## The parse_symtab and parse_dynsym
  ## methods can optionally take a block
  d.parse_dynsym do |sym|
    puts sprintf("DYNSYM: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_dyn_symbol_name(sym));
  end

  d.parse_symtab do |sym|
    puts sprintf("SYMTAB: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_sym_symbol_name(sym));
  end

  ## Print each symbol collected by parse_dynsym and parse_symtab
  #d.dynsym_symbols.each do |sym|
  #  puts sprintf("DYNSYM: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_dyn_symbol_name(sym));
  #end

  #d.symtab_symbols.each do |sym|
  #  puts sprintf("SYMTAB: %s %s 0x%08x %d %s\n", d.get_symbol_type(sym), d.get_symbol_bind(sym), sym.st_value.to_i, sym.st_size.to_i, d.get_sym_symbol_name(sym));
  #end
end
