#ifndef BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_TABLE_H
#define BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_TABLE_H

#include "elf_executable.h"
#include "elf_executable_header.h"
#include "elf_executable_section_header.h"
#include "elf_executable_symbol.h"

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

class ElfExecutable::SymbolTable {
public:
  static SymbolTable Parse(
      const char *const type,
      const uint8_t *const buf,
      const ElfExecutable::Header *const header,
      const std::vector<ElfExecutable::SectionHeader> &section_headers);

  const char *const get_type() const;

  const ElfExecutable::Symbol *const
      GetSymbolByAddress(const uint32_t address) const;
  const ElfExecutable::Symbol *const
      GetSymbolByName(const char *const name) const;
  std::string ToString() const;
private:
  SymbolTable(const char *const type,
      std::vector<ElfExecutable::Symbol> &&symbols,
      std::unordered_map<uint64_t, Symbol*> &&address_to_symbol,
      std::unordered_map<std::string, Symbol*> &&name_to_symbol);

  const char *const type_;
  const std::vector<ElfExecutable::Symbol> symbols_;
  const std::unordered_map<uint64_t, Symbol*> address_to_symbol_;
  const std::unordered_map<std::string, Symbol*> name_to_symbol_;
};

#endif // BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_TABLE_H
