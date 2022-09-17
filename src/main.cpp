#include <iostream>
#include <fstream>
#include "elf_module.h"
#include "mprotect.h"
using namespace std;

SYSV int printWrapper(const char *str) {
    return printf("%s", str);
}

int main(int argc, char *argv[]) {
    if (argc!=3) {
        cerr << "Usage: " << argv[0] << " [path/to/some_library.so] [some_function]" << endl;
        return -1;
    }

    ifstream ifs;
    ifs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);
    ifs.open(argv[1], ios_base::in | ios_base::binary);

    ElfModule::DynamicShims shims;

    // I'm relatively sure these can all be null
    // We could actually check the symbol table and see that they are weak
    shims["__gmon_start__"] = nullptr;
    shims["_ITM_registerTMCloneTable"] = nullptr;
    shims["_ITM_deregisterTMCloneTable"] = nullptr;
    shims["__cxa_finalize"] = nullptr;

    shims["printf"] = (const void*)printWrapper;
    ElfModule library(shims, ifs);

    // FIXME: Do this at allocation time
    unprotect(library.getImageBase(), 0x5000);

    const void *example_function_addr = library.getSymbolAddress(argv[2]);

    // FIXME: Messy syntax
    SYSV int(*example_function)() = (SYSV int (*)())example_function_addr;
    int r = example_function();
    printf("Ran %i\n", r);

    return 0;
}
