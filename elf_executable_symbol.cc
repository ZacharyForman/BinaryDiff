#include "elf_executable_symbol.h"

#include <elf.h>
#include <iomanip>
#include <string>
#include <sstream>

const char *const ElfSymbolTypeToString(uint8_t kInfo)
{
  switch (kInfo & 0xf) {
    case STT_NOTYPE: return "NOTYPE";
    case STT_OBJECT: return "OBJECT";
    case STT_FUNC: return "FUNCTION";
    case STT_SECTION: return "SECTION";
    case STT_FILE: return "FILE";
  }

  return "UNKNOWN";
}

const char *const ElfSymbolBindingToString(uint8_t kInfo)
{
  switch (kInfo >> 4) {
    case STB_LOCAL: return "LOCAL";
    case STB_GLOBAL: return "GLOBAL";
    case STB_WEAK: return "WEAK";
  }
  return "UNKNOWN";
}

const char *const ElfSymbolOtherToString(uint8_t kOther)
{
  switch (kOther & 0x7) {
    case STV_DEFAULT: return "DEFAULT";
    case STV_INTERNAL: return "INTERNAL";
    case STV_HIDDEN: return "HIDDEN";
    case STV_PROTECTED: return "PROTECTED";
  }
  return "UNKNOWN";
}

std::string ElfExecutable::Symbol::ToString() const
{
  std::stringstream res;
  res << std::hex
      << "Value: 0x"
      << std::setw(8) << std::setfill('0')
      << kValue << '\n'
      << "  Name:       " << kStringName << '\n'
      << std::dec
      << "  Size:       " << kSize << '\n'
      << "  Type:       " << ElfSymbolTypeToString(kInfo) << '\n'
      << "  Binding:    " << ElfSymbolBindingToString(kInfo) << '\n'
      << "  Visibility: " << ElfSymbolOtherToString(kOther) << '\n'
      << "  Section:    " << kSectionHeaderIndex << '\n';
  return res.str();
}
