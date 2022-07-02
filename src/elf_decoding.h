#ifndef __INC_ELF_DECODING_H_
#define __INC_ELF_DECODING_H_

#include <string>

const std::string &getElfTypeName(int type);
const std::string &getSectionTypeName(int type);
const std::string &getSegmentTypeName(int type);

const std::string &elfTypeToString(int type);
const std::string &sectionTypeToString(int type);
const std::string &segmentTypeToString(int type);

const std::string &symbolBindToString(int type);
const std::string &symbolTypeToString(int type);

std::string sectionFlagsToString(int flags);
std::string segmentFlagsToString(int flags);

#endif//__INC_ELF_DECODING_H_
