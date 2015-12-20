#include "elf_executable_symbol_table.h"

#include <sstream>
#include <string>

const ElfExecutable::Symbol *const
ElfExecutable::SymbolTable::GetSymbolByAddress(const uint32_t address) const
{
  auto it = kAddressToSymbol_.find(address);
  if (it == kAddressToSymbol_.end()) {
    return nullptr;
  }
  return it->second;
}

const ElfExecutable::Symbol *const
ElfExecutable::SymbolTable::GetSymbolByName(const char *const name) const
{
  auto it = kNameToSymbol_.find(name);
  if (it == kNameToSymbol_.end()) {
    return nullptr;
  }
  return it->second;
}

std::string ElfExecutable::SymbolTable::ToString() const
{
  std::stringstream res;

  return res.str();
}

ElfExecutable::SymbolTable::SymbolTable(
    std::vector<ElfExecutable::Symbol> &&symbols,
    std::unordered_map<uint64_t, ElfExecutable::Symbol*> &&address_to_symbol,
    std::unordered_map<std::string, ElfExecutable::Symbol*> &&name_to_symbol)
    : kSymbols_(symbols),
      kAddressToSymbol_(address_to_symbol),
      kNameToSymbol_(name_to_symbol) { }

ElfExecutable::SymbolTable *ElfExecutable::SymbolTable::Parse(
    const uint8_t *const buf,
    const ElfExecutable::Header *const header,
    const std::vector<ElfExecutable::SectionHeader> &section_headers)
{
  std::vector<ElfExecutable::Symbol> symbols;
  std::unordered_map<uint64_t, ElfExecutable::Symbol*> address_to_symbol;
  std::unordered_map<std::string, ElfExecutable::Symbol*> name_to_symbol;

  return new SymbolTable(std::move(symbols),
                         std::move(address_to_symbol),
                         std::move(name_to_symbol));
}
