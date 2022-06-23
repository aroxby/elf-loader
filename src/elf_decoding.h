#ifndef __INC_ELF_DECODING_H_
#define __INC_ELF_DECODING_H_

#include <string>

const std::string &getElfTypeName(int type);
const std::string &getSectionTypeName(int type);
const std::string &getSegmentTypeName(int type);

#endif//__INC_ELF_DECODING_H_
