#include "elf_executable_symbol.h"

#include <string>
#include <sstream>

std::string ElfExecutable::Symbol::ToString() const
{
  std::stringstream res;

  return res.str();
}
