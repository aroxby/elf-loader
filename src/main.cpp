#include <iostream>
#include <fstream>
#include "elf_image.h"
using namespace std;


int main(int argc, char *argv[]) {
    if (argc!=3) {
        cerr << "Usage: " << argv[0] << " [path/to/some_library.so] [some_function]" << endl;
        return -1;
    }

    ifstream ifs;
    ifs.exceptions(ifstream::eofbit | ifstream::failbit | ifstream::badbit);
    ifs.open(argv[1], ios_base::in | ios_base::binary);

    ElfImage library(ifs);
    library.dump(cout);

    return 0;
}
