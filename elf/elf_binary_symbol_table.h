#ifndef BINARY_MATCHER_ELF_BINARY_SYMBOL_TABLE_H
#define BINARY_MATCHER_ELF_BINARY_SYMBOL_TABLE_H

#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"
#include "elf/elf_binary_section_header.h"
#include "elf/elf_binary_symbol.h"

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

class ElfBinary::SymbolTable {
public:
  static SymbolTable Parse(
      const char *const type,
      const uint8_t *const buf,
      const ElfBinary::Header *const header,
      const std::vector<ElfBinary::SectionHeader> &section_headers);

  const char *type() const;

  const ElfBinary::Symbol *GetSymbolByAddress(const uint32_t address) const;
  const ElfBinary::Symbol *GetSymbolByName(const char *const name) const;

  // Constructs a string representation of the symbol table
  // that contains each symbol in the table's string representation.
  std::string ToString() const;
private:
  SymbolTable(const char *const type,
      std::vector<ElfBinary::Symbol> &&symbols,
      std::unordered_map<uint64_t, Symbol*> &&address_to_symbol,
      std::unordered_map<std::string, Symbol*> &&name_to_symbol);

  const char *const type_;
  const std::vector<ElfBinary::Symbol> symbols_;
  const std::unordered_map<uint64_t, Symbol*> address_to_symbol_;
  const std::unordered_map<std::string, Symbol*> name_to_symbol_;
};

#endif // BINARY_MATCHER_ELF_BINARY_SYMBOL_TABLE_H
