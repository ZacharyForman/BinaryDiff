#include "elf_executable.h"
#include "elf_executable_header.h"
#include "elf_executable_program_header.h"
#include "elf_executable_section_header.h"
#include "file.h"

#include <stdio.h>
#include <elf.h>

ElfExecutable *ElfExecutable::parse(const File &file)
{
  const uint8_t *const buf = file.buffer();

  std::unique_ptr<Header> header(ParseElfHeader(buf));
  if (!ValidElfHeader(header.get())) {
    return nullptr;
  }

  std::vector<ProgramHeader> program_headers
      = ParseElfProgramHeaders(buf, header.get());

  for (const ProgramHeader &program_header : program_headers) {
    if (!ValidElfProgramHeader(program_header)) {
      return nullptr;
    }
  }

  std::vector<SectionHeader> section_headers
      = ParseElfSectionHeaders(buf, header.get());

  for (const SectionHeader &section_header : section_headers) {
    if (!ValidElfSectionHeader(section_header)) {
      return nullptr;
    }
  }

  return new ElfExecutable(file, header.get(),
                           std::move(program_headers),
                           std::move(section_headers));
}

ElfExecutable::ElfExecutable(const File &file,
                             Header *header,
                             std::vector<ProgramHeader> &&program_headers,
                             std::vector<SectionHeader> &&section_headers)
  : Executable(file),
    header_(header),
    program_headers_(program_headers),
    section_headers_(section_headers) { }

Executable::Type ElfExecutable::GetType() const
{
  return Executable::Type::kElf;
}

const ElfExecutable::Header *const ElfExecutable::header()
{
  return header_.get();
}
