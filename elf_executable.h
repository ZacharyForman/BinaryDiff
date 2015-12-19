#ifndef BINARY_MATCHER_ELF_EXECUTABLE_H
#define BINARY_MATCHER_ELF_EXECUTABLE_H

#include "executable.h"

#include <memory>
#include <stdint.h>
#include <vector>

class ElfExecutable : public Executable {
public:
  static ElfExecutable *parse(const File &file);
  struct Header;
  struct ProgramHeader;
  struct SectionHeader;

  Executable::Type GetType() const;
  const Header *const header();
private:
  ElfExecutable(const File &file, Header *header,
                std::vector<ProgramHeader> &&program_headers,
                std::vector<SectionHeader> &&section_headers);
  std::unique_ptr<Header> header_;
  std::vector<ProgramHeader> program_headers_;
  std::vector<SectionHeader> section_headers_;
};

struct ElfExecutable::Header {
  const uint8_t kClass;
  const uint8_t kData;
  const uint8_t kShortVersion;
  const uint8_t kOsAbi;
  const uint8_t kAbiVersion;
  const uint16_t kType;
  const uint16_t kMachine;
  const uint32_t kLongVersion;
  const uint64_t kEntryPoint;
  const uint64_t kProgramHeaderOffset;
  const uint64_t kSectionHeaderOffset;
  const uint32_t kFlags;
  const uint16_t kHeaderSize;
  const uint16_t kProgramHeaderSize;
  const uint16_t kProgramHeaderCount;
  const uint16_t kSectionHeaderSize;
  const uint16_t kSectionHeaderCount;
  const uint16_t kSectionHeaderNamesIndex;
};

struct ElfExecutable::ProgramHeader {
  const uint32_t kType;
  const uint32_t kFlags;
  const uint64_t kOffset;
  const uint64_t kVirtualAddress;
  const uint64_t kPhysicalAddress;
  const uint64_t kFileSize;
  const uint64_t kMemorySize;
  const uint64_t kAlign;
};

struct ElfExecutable::SectionHeader {
  const uint32_t kName;
  const uint32_t kType;
  const uint64_t kFlags;
  const uint64_t kAddress;
  const uint64_t kOffset;
  const uint64_t kSize;
  const uint32_t kLink;
  const uint32_t kInfo;
  const uint64_t kAddressAlignment;
  const uint64_t kEntrySize;
};

#endif // BINARY_MATCHER_ELF_EXECUTABLE_H
