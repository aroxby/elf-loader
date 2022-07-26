#include <cstdio>
#ifndef __unix__
    #warning You are not targetting Unix.  Your complier will probably NOT generate an ELF binary.
#endif

extern "C" int example_function() {
    // printf is used here (instead of cout) because it will be easier to hack later
    return printf("This is the example lib!\n");
}
