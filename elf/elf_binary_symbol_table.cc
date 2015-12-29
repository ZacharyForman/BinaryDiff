#include "elf/elf_binary_symbol_table.h"

#include <elf.h>
#include <sstream>
#include <string>
#include <string.h>

using Header = ElfBinary::Header;
using SectionHeader = ElfBinary::SectionHeader;
using Symbol = ElfBinary::Symbol;
using SymbolTable = ElfBinary::SymbolTable;

#define EXTRACT_ELF_FIELD(bits, offset) \
  *(reinterpret_cast<const uint##bits##_t*>(buf+(offset)))

namespace {

// Set of helper methods that extract fields from
// the buffer.

inline static uint32_t
ExtractElfSymbolName(const uint8_t *const buf,
    const Header *const)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

inline static uint64_t
ExtractElfSymbolValue(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 4);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 8);
    default: return ~0ULL;
  }
}

inline static uint64_t
ExtractElfSymbolSize(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 8);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 16);
    default: return ~0ULL;
  }
}

inline static uint8_t
ExtractElfSymbolInfo(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(8, 12);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(8, 4);
    default: return 0xFF;
  }
}

inline static uint8_t
ExtractElfSymbolOther(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(8, 13);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(8, 5);
    default: return 0xFF;
  }
}

inline static uint16_t
ExtractElfSymbolSectionHeaderIndex(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, 14);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, 6);
    default: return 0xFFFF;
  }
}

} // namespace

#undef EXTRACT_ELF_FIELD

const char *SymbolTable::type() const
{
  return type_;
}

const Symbol *SymbolTable::GetSymbolByAddress(const uint32_t address) const
{
  auto it = address_to_symbol_.find(address);
  if (it == address_to_symbol_.end()) {
    return nullptr;
  }
  return it->second;
}

const Symbol *SymbolTable::GetSymbolByName(const char *const name) const
{
  auto it = name_to_symbol_.find(name);
  if (it == name_to_symbol_.end()) {
    return nullptr;
  }
  return it->second;
}

std::string SymbolTable::ToString() const
{
  std::stringstream res;
  for (unsigned i = 0; i < symbols_.size(); i++) {
    res << symbols_[i].ToString() << '\n';
  }
  return res.str();
}

SymbolTable::SymbolTable(
    const char *const type,
    std::vector<Symbol> &&symbols,
    std::unordered_map<uint64_t, Symbol*> &&address_to_symbol,
    std::unordered_map<std::string, Symbol*> &&name_to_symbol)
    : type_(type),
      symbols_(symbols),
      address_to_symbol_(address_to_symbol),
      name_to_symbol_(name_to_symbol) { }

SymbolTable::~SymbolTable() { }

SymbolTable SymbolTable::Parse(
    const char *const table_type,
    const uint8_t *const buf,
    const Header *const header,
    const std::vector<SectionHeader> &section_headers)
{
  std::string strtab_name(table_type);
  strtab_name.replace(strtab_name.find("sym"), 3, "str");

  const SectionHeader *symbol_table_header = nullptr;
  const SectionHeader *string_table_header = nullptr;

  // Extract the string and symbol table headers.
  for (const SectionHeader &section_header : section_headers) {
    if (!strcmp(table_type, section_header.kStringName)) {
      symbol_table_header = &section_header;
    }
    if (!strcmp(strtab_name.c_str(), section_header.kStringName)) {
      string_table_header = &section_header;
    }
  }

  if (!symbol_table_header || !string_table_header) {
    return SymbolTable("N/A",
                       std::vector<Symbol>(),
                       std::unordered_map<uint64_t, Symbol*>(),
                       std::unordered_map<std::string, Symbol*>());
  }

  const uint64_t kSize = symbol_table_header->kSize ;
  const uint64_t kEntrySize = symbol_table_header->kEntrySize;
  const uint64_t kEntries = kSize / kEntrySize;

  const uint8_t *const symbol_table_base
        = buf + symbol_table_header->kOffset;
  const char *const string_table_base
      = reinterpret_cast<const char*>(buf) + string_table_header->kOffset;

  std::vector<Symbol> symbols;
  symbols.reserve(kEntries);

  for (unsigned i = 0; i < kEntries; i++) {
    const uint8_t *symbol_table_entry = symbol_table_base + i*kEntrySize;

    symbols.push_back(Symbol{
      ExtractElfSymbolName(symbol_table_entry, header),
      string_table_base + ExtractElfSymbolName(symbol_table_entry, header),
      ExtractElfSymbolValue(symbol_table_entry, header),
      ExtractElfSymbolSize(symbol_table_entry, header),
      ExtractElfSymbolInfo(symbol_table_entry, header),
      ExtractElfSymbolOther(symbol_table_entry, header),
      ExtractElfSymbolSectionHeaderIndex(symbol_table_entry, header),
    });
  }

  std::unordered_map<uint64_t, Symbol*> address_to_symbol;
  std::unordered_map<std::string, Symbol*> name_to_symbol;
  address_to_symbol.reserve(kEntries);
  name_to_symbol.reserve(kEntries);

  for (Symbol &symbol : symbols) {
    address_to_symbol[symbol.kValue] = &symbol;
    name_to_symbol[std::string(symbol.kStringName)] = &symbol;
  }

  return SymbolTable(table_type,
                     std::move(symbols),
                     std::move(address_to_symbol),
                     std::move(name_to_symbol));
}
