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

#endif // BINARY_MATCHER_ELF_EXECUTABLE_H
