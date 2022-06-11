#include <iostream>
#include "loader.h"
using namespace std;


int main(int argc, char *argv[]) {
    if (argc!=3) {
        cerr << "Usage: " << argv[0] << " [path/to/some_library.so] [some_function]" << endl;
        return -1;
    }

    ElfLoader loader(argv[1]);

    return 0;
}
