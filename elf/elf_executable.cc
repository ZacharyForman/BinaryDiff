#include "elf/elf_executable.h"
#include "elf/elf_executable_header.h"
#include "elf/elf_executable_program_header.h"
#include "elf/elf_executable_section_header.h"
#include "elf/elf_executable_symbol_table.h"
#include "file.h"

#include <sstream>
#include <stdio.h>
#include <string.h>
#include <elf.h>

ElfExecutable *ElfExecutable::ParseFile(const File *file)
{
  const uint8_t *const buf = file->buffer();

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

  std::vector<SymbolTable> symbol_tables = {
    SymbolTable::Parse(".dynsym", buf, header.get(), section_headers),
    SymbolTable::Parse(".symtab", buf, header.get(), section_headers),
  };

  return new ElfExecutable(file, header.release(),
                           std::move(program_headers),
                           std::move(section_headers),
                           std::move(symbol_tables));
}

ElfExecutable::ElfExecutable(const File *file,
                             Header *header,
                             std::vector<ProgramHeader> &&program_headers,
                             std::vector<SectionHeader> &&section_headers,
                             std::vector<SymbolTable> &&symbol_tables)
  : Executable(file),
    header_(header),
    program_headers_(program_headers),
    section_headers_(section_headers),
    symbol_tables_(symbol_tables) { }

Executable::Type ElfExecutable::GetType() const
{
  return Executable::Type::kElf;
}

const ElfExecutable::Header *ElfExecutable::header() const
{
  return header_.get();
}

const std::vector<ElfExecutable::ProgramHeader>
&ElfExecutable::program_headers() const
{
  return program_headers_;
}

const std::vector<ElfExecutable::SectionHeader>
&ElfExecutable::section_headers() const
{
  return section_headers_;
}

std::string ElfExecutable::ToString() const
{
  std::stringstream res;
  res << filename() << ":\n"
      << header_->ToString() << '\n';
  for (unsigned i = 0; i < program_headers_.size(); i++) {
    res << "\nProgram Header " << i << ": "
        << program_headers_[i].ToString() << '\n';
  }
  for (unsigned i = 0; i < section_headers_.size(); i++) {
    res << "\nSection Header " << i << ": "
        << section_headers_[i].ToString() << '\n';
  }
  for (unsigned i = 0; i < symbol_tables_.size(); i++) {
    if (!strcmp(symbol_tables_[i].get_type(), "N/A")) {
      continue;
    }
    res << "\nSymbol table " << symbol_tables_[i].get_type() << ":"
        << symbol_tables_[i].ToString() << '\n';
  }
  return res.str();
}
