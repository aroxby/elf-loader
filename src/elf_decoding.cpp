#include <map>
#include <string>
#include <sstream>
#include "elf_common.h"
#include "elf_decoding.h"

typedef std::map<int, std::string> Index;

const std::string &getNameOrUnknown(const Index &map, int type) {
    const static std::string unkown_name = "Unknown";
    auto iterator = map.find(type);
    if(iterator == map.end()) {
        return unkown_name;
    } else {
        return iterator->second;
    }
}

const std::string &getElfTypeName(int type) {
    const static Index elf_types = {
        {ET_REL, "Relocatable"},
        {ET_EXEC, "Executable"},
        {ET_DYN, "Shared object"},
        {ET_CORE, "Core file"},
    };
    return getNameOrUnknown(elf_types, type);
}

const std::string &getSectionTypeName(int type) {
    const static Index section_types = {
        {SHT_NULL, "inactive"},
        {SHT_PROGBITS, "program defined information"},
        {SHT_SYMTAB, "symbol table section"},
        {SHT_STRTAB, "string table section"},
        {SHT_RELA, "relocation section with addends"},
        {SHT_HASH, "symbol hash table section"},
        {SHT_DYNAMIC, "dynamic section"},
        {SHT_NOTE, "note section"},
        {SHT_NOBITS, "no space section"},
        {SHT_REL, "relocation section - no addends"},
        {SHT_SHLIB, "reserved - purpose unknown"},
        {SHT_DYNSYM, "dynamic symbol table section"},
        {SHT_INIT_ARRAY, "Initialization function pointers"},
        {SHT_FINI_ARRAY, "Termination function pointers"},
        {SHT_PREINIT_ARRAY, "Pre-initialization function pointers"},
        {SHT_GROUP, "Section group."},
        {SHT_SYMTAB_SHNDX, "Section indexes"},
        {SHT_GNU_HASH, "Hash"},
        {SHT_GNU_LIBLIST, "Library List"},
        {SHT_GNU_verdef, "Symbol versions provided"},
        {SHT_GNU_verneed, "Symbol versions required"},
        {SHT_GNU_versym, "Symbol version table"},
        {SHT_AMD64_UNWIND, "unwind information"},
    };
    return getNameOrUnknown(section_types, type);
}

const std::string &getSegmentTypeName(int type) {
    const static Index segment_types = {
        {PT_NULL, "Unused"},
        {PT_LOAD, "Loadable segment"},
        {PT_DYNAMIC, "Dynamic linking information segment"},
        {PT_INTERP, "Pathname of interpreter"},
        {PT_NOTE, "Auxiliary information"},
        {PT_SHLIB, "Reserved"},
        {PT_PHDR, "Location of program header itself"},
        {PT_TLS, "Thread local storage segment"},
        {PT_SUNW_UNWIND, "AMD64 UNWIND program header"},
        {PT_GNU_EH_FRAME, "Gnu EH Frame?"},
        {PT_GNU_STACK, "Gnu Stack?"},
        {PT_GNU_RELRO, "Gnu Relocate?"},
        {PT_GNU_PROPERTY, "Gnu Property?"},
        {PT_DUMP_DELTA, "Map for kernel Dumps"},
        {PT_SUNWBSS, "Sun Specific segment"},
        {PT_SUNWSTACK, "Describes the stack segment"},
        {PT_SUNWDTRACE, "Private"},
        {PT_SUNWCAP, "Hard/soft capabilities segment"},
    };
    return getNameOrUnknown(segment_types, type);
}

const std::string &elfTypeToString(int type) {
    const static Index elf_types = {
        {ET_REL, "ET_REL"},
        {ET_EXEC, "ET_EXEC"},
        {ET_DYN, "ET_DYN"},
        {ET_CORE, "ET_CORE"},
    };
    return getNameOrUnknown(elf_types, type);
}

const std::string &sectionTypeToString(int type) {
    const static Index section_types = {
        {SHT_NULL, "SHT_NULL"},
        {SHT_PROGBITS, "SHT_PROGBITS"},
        {SHT_SYMTAB, "SHT_SYMTAB"},
        {SHT_STRTAB, "SHT_STRTAB"},
        {SHT_RELA, "SHT_RELA"},
        {SHT_HASH, "SHT_HASH"},
        {SHT_DYNAMIC, "SHT_DYNAMIC"},
        {SHT_NOTE, "SHT_NOTE"},
        {SHT_NOBITS, "SHT_NOBITS"},
        {SHT_REL, "SHT_REL"},
        {SHT_SHLIB, "SHT_SHLIB"},
        {SHT_DYNSYM, "SHT_DYNSYM"},
        {SHT_INIT_ARRAY, "SHT_INIT_ARRAY"},
        {SHT_FINI_ARRAY, "SHT_FINI_ARRAY"},
        {SHT_PREINIT_ARRAY, "SHT_PREINIT_ARRAY"},
        {SHT_GROUP, "SHT_GROUP"},
        {SHT_SYMTAB_SHNDX, "SHT_SYMTAB_SHNDX"},
        {SHT_GNU_HASH, "SHT_GNU_HASH"},
        {SHT_GNU_LIBLIST, "SHT_GNU_LIBLIST"},
        {SHT_GNU_verdef, "SHT_GNU_verdef"},
        {SHT_GNU_verneed, "SHT_GNU_verneed"},
        {SHT_GNU_versym, "SHT_GNU_versym"},
        {SHT_AMD64_UNWIND, "SHT_AMD64_UNWIND"},
    };
    return getNameOrUnknown(section_types, type);
}

const std::string &segmentTypeToString(int type) {
    const static Index segment_types = {
        {PT_NULL, "PT_NULL"},
        {PT_LOAD, "PT_LOAD"},
        {PT_DYNAMIC, "PT_DYNAMIC"},
        {PT_INTERP, "PT_INTERP"},
        {PT_NOTE, "PT_NOTE"},
        {PT_SHLIB, "PT_SHLIB"},
        {PT_PHDR, "PT_PHDR"},
        {PT_TLS, "PT_TLS"},
        {PT_SUNW_UNWIND, "PT_SUNW_UNWIND"},
        {PT_GNU_EH_FRAME, "PT_GNU_EH_FRAME"},
        {PT_GNU_STACK, "PT_GNU_STACK"},
        {PT_GNU_RELRO, "PT_GNU_RELRO"},
        {PT_GNU_PROPERTY, "PT_GNU_PROPERTY"},
        {PT_DUMP_DELTA, "PT_DUMP_DELTA"},
        {PT_SUNWBSS, "PT_SUNWBSS"},
        {PT_SUNWSTACK, "PT_SUNWSTACK"},
        {PT_SUNWDTRACE, "PT_SUNWDTRACE"},
        {PT_SUNWCAP, "PT_SUNWCAP"},
    };
    return getNameOrUnknown(segment_types, type);
}

const std::string &symbolBindToString(int type) {
    const static Index bind_types = {
        {STB_LOCAL, "STB_LOCAL"},
        {STB_GLOBAL, "STB_GLOBAL"},
        {STB_WEAK, "STB_WEAK"},
    };
    return getNameOrUnknown(bind_types, type);
}

const std::string &symbolTypeToString(int type) {
    const static Index type_types = {
        {STT_NOTYPE, "STT_NOTYPE"},
        {STT_OBJECT, "STT_OBJECT"},
        {STT_FUNC, "STT_FUNC"},
        {STT_SECTION, "STT_SECTION"},
        {STT_FILE, "STT_FILE"},
        {STT_COMMON, "STT_COMMON"},
        {STT_TLS, "STT_TLS"},
        {STT_NUM, "STT_NUM"},
        {STT_GNU_IFUNC, "STT_GNU_IFUNC"},
    };
    return getNameOrUnknown(type_types, type);
}

const std::string &relocationTypeToString(int type) {
    const static Index type_types = {
        {R_X86_64_NONE, "R_X86_64_NONE"},
        {R_X86_64_64, "R_X86_64_64"},
        {R_X86_64_PC32, "R_X86_64_PC32"},
        {R_X86_64_GOT32, "R_X86_64_GOT32"},
        {R_X86_64_PLT32, "R_X86_64_PLT32"},
        {R_X86_64_COPY, "R_X86_64_COPY"},
        {R_X86_64_GLOB_DAT, "R_X86_64_GLOB_DAT"},
        {R_X86_64_JMP_SLOT, "R_X86_64_JMP_SLOT"},
        {R_X86_64_RELATIVE, "R_X86_64_RELATIVE"},
        {R_X86_64_GOTPCREL, "R_X86_64_GOTPCREL"},
        {R_X86_64_32, "R_X86_64_32"},
        {R_X86_64_32S, "R_X86_64_32S"},
        {R_X86_64_16, "R_X86_64_16"},
        {R_X86_64_PC16, "R_X86_64_PC16"},
        {R_X86_64_8, "R_X86_64_8"},
        {R_X86_64_PC8, "R_X86_64_PC8"},
        {R_X86_64_DTPMOD64, "R_X86_64_DTPMOD64"},
        {R_X86_64_DTPOFF64, "R_X86_64_DTPOFF64"},
        {R_X86_64_TPOFF64, "R_X86_64_TPOFF64"},
        {R_X86_64_TLSGD, "R_X86_64_TLSGD"},
        {R_X86_64_TLSLD, "R_X86_64_TLSLD"},
        {R_X86_64_DTPOFF32, "R_X86_64_DTPOFF32"},
        {R_X86_64_GOTTPOFF, "R_X86_64_GOTTPOFF"},
        {R_X86_64_TPOFF32, "R_X86_64_TPOFF32"},
        {R_X86_64_IRELATIVE, "R_X86_64_IRELATIVE"},
    };
    return getNameOrUnknown(type_types, type);
}

const std::string &dynamicEntryTypeToString(int type) {
    const static Index type_types = {
        {DT_NULL, "DT_NULL"},
        {DT_NEEDED, "DT_NEEDED"},
        {DT_PLTRELSZ, "DT_PLTRELSZ"},
        {DT_PLTGOT, "DT_PLTGOT"},
        {DT_HASH, "DT_HASH"},
        {DT_STRTAB, "DT_STRTAB"},
        {DT_SYMTAB, "DT_SYMTAB"},
        {DT_RELA, "DT_RELA"},
        {DT_RELASZ, "DT_RELASZ"},
        {DT_RELAENT, "DT_RELAENT"},
        {DT_STRSZ, "DT_STRSZ"},
        {DT_SYMENT, "DT_SYMENT"},
        {DT_INIT, "DT_INIT"},
        {DT_FINI, "DT_FINI"},
        {DT_SONAME, "DT_SONAME"},
        {DT_RPATH, "DT_RPATH"},
        {DT_SYMBOLIC, "DT_SYMBOLIC"},
        {DT_REL, "DT_REL"},
        {DT_RELSZ, "DT_RELSZ"},
        {DT_RELENT, "DT_RELENT"},
        {DT_PLTREL, "DT_PLTREL"},
        {DT_DEBUG, "DT_DEBUG"},
        {DT_TEXTREL, "DT_TEXTREL"},
        {DT_JMPREL, "DT_JMPREL"},
        {DT_BIND_NOW, "DT_BIND_NOW"},
        {DT_INIT_ARRAY, "DT_INIT_ARRAY"},
        {DT_FINI_ARRAY, "DT_FINI_ARRAY"},
        {DT_INIT_ARRAYSZ, "DT_INIT_ARRAYSZ"},
        {DT_FINI_ARRAYSZ, "DT_FINI_ARRAYSZ"},
        {DT_RUNPATH, "DT_RUNPATH"},
        {DT_FLAGS, "DT_FLAGS"},
        {DT_ENCODING, "DT_ENCODING"},
        {DT_PREINIT_ARRAY, "DT_PREINIT_ARRAY"},
        {DT_PREINIT_ARRAYSZ, "DT_PREINIT_ARRAYSZ"},
        {DT_MAXPOSTAGS, "DT_MAXPOSTAGS"},
        {DT_CHECKSUM, "DT_CHECKSUM"},
        {DT_PLTPADSZ, "DT_PLTPADSZ"},
        {DT_MOVEENT, "DT_MOVEENT"},
        {DT_MOVESZ, "DT_MOVESZ"},
        {DT_FEATURE, "DT_FEATURE"},
        {DT_POSFLAG_1, "DT_POSFLAG_1"},
        {DT_SYMINSZ, "DT_SYMINSZ"},
        {DT_SYMINENT, "DT_SYMINENT"},
        {DT_GNU_HASH, "DT_GNU_HASH"},
        {DT_CONFIG, "DT_CONFIG"},
        {DT_DEPAUDIT, "DT_DEPAUDIT"},
        {DT_AUDIT, "DT_AUDIT"},
        {DT_PLTPAD, "DT_PLTPAD"},
        {DT_MOVETAB, "DT_MOVETAB"},
        {DT_SYMINFO, "DT_SYMINFO"},
        {DT_VERSYM, "DT_VERSYM"},
        {DT_RELACOUNT, "DT_RELACOUNT"},
        {DT_RELCOUNT, "DT_RELCOUNT"},
        {DT_FLAGS_1, "DT_FLAGS_1"},
        {DT_VERDEF, "DT_VERDEF"},
        {DT_VERDEFNUM, "DT_VERDEFNUM"},
        {DT_VERNEED, "DT_VERNEED"},
        {DT_VERNEEDNUM, "DT_VERNEEDNUM"},
    };
    return getNameOrUnknown(type_types, type);
}

std::string flagsToString(const Index &map, int flags) {
    const static std::string sep(" | ");
    const static std::string extra("?");

    if(!flags) {
        return "";
    } else {
        std::stringstream sstream;
        for(auto iterator : map) {
            if(flags & iterator.first) {
                sstream << sep << iterator.second;
            }
            flags &= ~iterator.first;
        }
        if(flags) {
            sstream << sep << extra;
        }

        std::string flags_str = sstream.str();
        flags_str.erase(0, sep.length());
        return flags_str;
    }
}

std::string sectionFlagsToString(int flags) {
    const static Index section_flags = {
        {SHF_WRITE, "SHF_WRITE"},
        {SHF_ALLOC, "SHF_ALLOC"},
        {SHF_EXECINSTR, "SHF_EXECINSTR"},
        {SHF_MERGE, "SHF_MERGE"},
        {SHF_STRINGS, "SHF_STRINGS"},
        {SHF_INFO_LINK, "SHF_INFO_LINK"},
        {SHF_LINK_ORDER, "SHF_LINK_ORDER"},
        {SHF_OS_NONCONFORMING, "SHF_OS_NONCONFORMING"},
        {SHF_GROUP, "SHF_GROUP"},
        {SHF_TLS, "SHF_TLS"},
        {SHF_MASKOS, "SHF_MASKOS"},
        {SHF_MASKPROC, "SHF_MASKPROC"},
    };
    return flagsToString(section_flags, flags);
}

std::string segmentFlagsToString(int flags) {
    const static Index segment_flags = {
        {PF_X, "PF_X"},
        {PF_W, "PF_W"},
        {PF_R, "PF_R"},
        {PF_MASKOS, "PF_MASKOS"},
        {PF_MASKPROC, "PF_MASKPROC"},
    };
    return flagsToString(segment_flags, flags);
}
