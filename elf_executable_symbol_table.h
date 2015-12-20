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
  static SymbolTable *Parse(const uint8_t *const buf,
      const ElfExecutable::Header *const header,
      const std::vector<ElfExecutable::SectionHeader> &section_headers);

  const ElfExecutable::Symbol *const
      GetSymbolByAddress(const uint32_t address) const;
  const ElfExecutable::Symbol *const
      GetSymbolByName(const char *const name) const;
  std::string ToString() const;
private:
  SymbolTable(std::vector<ElfExecutable::Symbol> &&symbols,
      std::unordered_map<uint64_t, Symbol*> &&address_to_symbol,
      std::unordered_map<std::string, Symbol*> &&name_to_symbol);

  const std::vector<ElfExecutable::Symbol> kSymbols_;
  const std::unordered_map<uint64_t, Symbol*> kAddressToSymbol_;
  const std::unordered_map<std::string, Symbol*> kNameToSymbol_;
};

#endif // BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_TABLE_H
