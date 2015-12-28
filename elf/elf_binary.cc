#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"
#include "elf/elf_binary_program_header.h"
#include "elf/elf_binary_section_header.h"
#include "elf/elf_binary_symbol_table.h"
#include "file.h"

#include <sstream>
#include <stdio.h>
#include <string.h>
#include <elf.h>

ElfBinary *ElfBinary::ParseFile(const File *file)
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

  return new ElfBinary(file, header.release(),
                           std::move(program_headers),
                           std::move(section_headers),
                           std::move(symbol_tables));
}

ElfBinary::ElfBinary(const File *file,
                             Header *header,
                             std::vector<ProgramHeader> &&program_headers,
                             std::vector<SectionHeader> &&section_headers,
                             std::vector<SymbolTable> &&symbol_tables)
  : Binary(file),
    header_(header),
    program_headers_(program_headers),
    section_headers_(section_headers),
    symbol_tables_(symbol_tables) { }

Binary::Type ElfBinary::GetType() const
{
  return Binary::Type::kElf;
}

const ElfBinary::Header *ElfBinary::header() const
{
  return header_.get();
}

const std::vector<ElfBinary::ProgramHeader>
&ElfBinary::program_headers() const
{
  return program_headers_;
}

const std::vector<ElfBinary::SectionHeader>
&ElfBinary::section_headers() const
{
  return section_headers_;
}

const std::vector<ElfBinary::SymbolTable>
&ElfBinary::symbol_tables() const
{
  return symbol_tables_;
}

std::string ElfBinary::ToString() const
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
    if (!strcmp(symbol_tables_[i].type(), "N/A")) {
      continue;
    }
    res << "\nSymbol table " << symbol_tables_[i].type() << ":"
        << symbol_tables_[i].ToString() << '\n';
  }
  return res.str();
}
