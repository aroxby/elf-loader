#include <iostream>
#include <fstream>
#include "elf_module.h"
using namespace std;


int main(int argc, char *argv[]) {
    if (argc!=3) {
        cerr << "Usage: " << argv[0] << " [path/to/some_library.so] [some_function]" << endl;
        return -1;
    }

    ifstream ifs;
    ifs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);
    ifs.open(argv[1], ios_base::in | ios_base::binary);

    ElfModule library(ElfModule::DynamicShims(), ifs);

    return 0;
}
