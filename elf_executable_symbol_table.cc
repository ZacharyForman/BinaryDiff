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
    const char *const type,
    std::vector<ElfExecutable::Symbol> &&symbols,
    std::unordered_map<uint64_t, ElfExecutable::Symbol*> &&address_to_symbol,
    std::unordered_map<std::string, ElfExecutable::Symbol*> &&name_to_symbol)
    : kType_(type),
      kSymbols_(symbols),
      kAddressToSymbol_(address_to_symbol),
      kNameToSymbol_(name_to_symbol) { }

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
  const uint64_t kEntries = kSize/ kEntrySize;

  const uint8_t *const symbol_table_base = buf + symbol_table_header->kOffset;

  for (unsigned i = 0; i < kEntries; i++) {
    const uint16_t kSectionHeaderIndex
        = ExtractElfSymbolSectionHeaderIndex(symbol_table_base + i*kEntrySize,
                                             header);
    const uint32_t kName
        = ExtractElfSymbolName(symbol_table_base + i*kEntrySize, header);

    const uint8_t *const string_table_base
        = buf + section_headers[kSectionHeaderIndex].kOffset;

    symbols.push_back(Symbol{
      kName,
      reinterpret_cast<const char *const>(string_table_base+kName),
      ExtractElfSymbolValue(symbol_table_base + i*kEntrySize, header),
      ExtractElfSymbolSize(symbol_table_base + i*kEntrySize, header),
      ExtractElfSymbolInfo(symbol_table_base + i*kEntrySize, header),
      ExtractElfSymbolOther(symbol_table_base + i*kEntrySize, header),
      kSectionHeaderIndex,
    });
  }

  std::unordered_map<uint64_t, ElfExecutable::Symbol*> address_to_symbol;
  std::unordered_map<std::string, ElfExecutable::Symbol*> name_to_symbol;

  for (ElfExecutable::Symbol &symbol : symbols) {
    // printf("Symbol: %s <=> %lu\n", symbol.kStringName, symbol.kValue);
    address_to_symbol[symbol.kValue] = &symbol;
    name_to_symbol[std::string(symbol.kStringName)] = &symbol;
  }

  return SymbolTable(table_type,
                     std::move(symbols),
                     std::move(address_to_symbol),
                     std::move(name_to_symbol));
}
