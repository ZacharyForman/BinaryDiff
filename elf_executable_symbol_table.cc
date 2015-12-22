#include "elf_executable_symbol_table.h"

#include <elf.h>
#include <sstream>
#include <string>
#include <string.h>

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(buf+(offset)))

namespace {

static uint32_t
ExtractElfSymbolName(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

static uint64_t
ExtractElfSymbolValue(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 4);
  } else {
    return EXTRACT_ELF_FIELD(64, 8);
  }
}

static uint64_t
ExtractElfSymbolSize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 8);
  } else {
    return EXTRACT_ELF_FIELD(64, 16);
  }
}

static uint8_t
ExtractElfSymbolInfo(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(8, 12);
  } else {
    return EXTRACT_ELF_FIELD(8, 4);
  }
}

static uint8_t
ExtractElfSymbolOther(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(8, 13);
  } else {
    return EXTRACT_ELF_FIELD(8, 5);
  }
}

static uint16_t
ExtractElfSymbolSectionHeaderIndex(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(16, 14);
  } else {
    return EXTRACT_ELF_FIELD(16, 6);
  }
}

} // namespace

#undef EXTRACT_ELF_FIELD

const char *const ElfExecutable::SymbolTable::get_type() const
{
  return type_;
}

const ElfExecutable::Symbol *const
ElfExecutable::SymbolTable::GetSymbolByAddress(const uint32_t address) const
{
  auto it = address_to_symbol_.find(address);
  if (it == address_to_symbol_.end()) {
    return nullptr;
  }
  return it->second;
}

const ElfExecutable::Symbol *const
ElfExecutable::SymbolTable::GetSymbolByName(const char *const name) const
{
  auto it = name_to_symbol_.find(name);
  if (it == name_to_symbol_.end()) {
    return nullptr;
  }
  return it->second;
}

std::string ElfExecutable::SymbolTable::ToString() const
{
  std::stringstream res;
  for (unsigned i = 0; i < symbols_.size(); i++) {
    res << "[" << i << "]" << " " << symbols_[i].ToString() << "\n";
  }
  return res.str();
}

ElfExecutable::SymbolTable::SymbolTable(
    const char *const type,
    std::vector<ElfExecutable::Symbol> &&symbols,
    std::unordered_map<uint64_t, ElfExecutable::Symbol*> &&address_to_symbol,
    std::unordered_map<std::string, ElfExecutable::Symbol*> &&name_to_symbol)
    : type_(type),
      symbols_(symbols),
      address_to_symbol_(address_to_symbol),
      name_to_symbol_(name_to_symbol) { }

ElfExecutable::SymbolTable ElfExecutable::SymbolTable::Parse(
    const char *const table_type,
    const uint8_t *const buf,
    const ElfExecutable::Header *const header,
    const std::vector<ElfExecutable::SectionHeader> &section_headers)
{
  std::vector<ElfExecutable::Symbol> symbols;

  const ElfExecutable::SectionHeader *symbol_table_header;

  for (const ElfExecutable::SectionHeader &section_header : section_headers) {
    if (!strcmp(table_type, section_header.kStringName)) {
      symbol_table_header = &section_header;
    }
  }

  const uint64_t kSize = symbol_table_header->kSize ;
  const uint64_t kEntrySize = symbol_table_header->kEntrySize;
  const uint64_t kEntries = kSize / kEntrySize;

  for (unsigned i = 0; i < kEntries; i++) {
    const uint8_t *const symbol_table_entry
        = buf + symbol_table_header->kOffset + i*kEntrySize;
    const uint32_t kSymbolName
        = ExtractElfSymbolName(symbol_table_entry, header);
    const uint64_t kSymbolValue
        = ExtractElfSymbolValue(symbol_table_entry, header);
    const uint64_t kSymbolSize
        = ExtractElfSymbolSize(symbol_table_entry, header);
    const uint8_t kSymbolInfo
        = ExtractElfSymbolInfo(symbol_table_entry, header);
    const uint8_t kSymbolOther
        = ExtractElfSymbolOther(symbol_table_entry, header);
    const uint16_t kSymbolSectionHeaderIndex
        = ExtractElfSymbolSectionHeaderIndex(symbol_table_entry, header);

    symbols.push_back(Symbol{
      kSymbolName,
      "UNKNOWN",
      kSymbolValue,
      kSymbolSize,
      kSymbolInfo,
      kSymbolOther,
      kSymbolSectionHeaderIndex,
    });
  }

  std::unordered_map<uint64_t, ElfExecutable::Symbol*> address_to_symbol;
  std::unordered_map<std::string, ElfExecutable::Symbol*> name_to_symbol;

  for (ElfExecutable::Symbol &symbol : symbols) {
    address_to_symbol[symbol.kValue] = &symbol;
    name_to_symbol[std::string(symbol.kStringName)] = &symbol;
  }

  return SymbolTable(table_type,
                     std::move(symbols),
                     std::move(address_to_symbol),
                     std::move(name_to_symbol));
}
