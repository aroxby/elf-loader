#include "exceptions.h"
#include "elf_module.h"
#include "elf_decoding.h"
using namespace std;

ElfModule::ElfModule(const DynamicShims &shims, std::istream &is) : ElfImage(is), shims(shims) {
    processRelocations();
}

void ElfModule::processRelocations() {
    for(const auto &iterator : getRelocations()) {
        const ElfRelocations &relocation_block = *iterator.second.get();
        for(const Elf64_Rela relocation : relocation_block.relocations) {
            Elf64_Xword relocation_type = ELF64_R_TYPE_ID(relocation.r_info);
            Elf64_Xword symbol_index = ELF64_R_SYM(relocation.r_info);
            const Elf64_Sym &symbol = relocation_block.symbols.symbols[symbol_index];
            const char *symbol_name = &relocation_block.symbols.strings[symbol.st_name];

            processRelocation(
                relocation.r_offset, relocation_type, relocation.r_addend, symbol_name
            );
        }
    }
}

void ElfModule::processRelocation(Elf64_Addr offset, Elf64_Xword type, Elf64_Sxword addend, const char *symbol_name) {
    Elf64_Xword dest_value;

    switch(type) {
        case R_X86_64_RELATIVE:
            dest_value = (Elf64_Xword)getImageBase() + addend;
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JMP_SLOT:
            dest_value = (Elf64_Xword)getShim(symbol_name);
            break;

        default:
            throw UnexpectedRelocationType(relocationTypeToString(type));
            break;
    }

    char *dest_addr = (char*)getImageBase() + offset;
    *(Elf64_Xword*)dest_addr = dest_value;
}

const void *ElfModule::getShim(const char *symbol_name) const {
    auto iterator = shims.find(symbol_name);
    if(iterator == shims.end()) {
        throw UnresolvedSymbol(symbol_name);
    } else {
        return iterator->second;
    }
}
