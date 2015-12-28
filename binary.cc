#include "elf/elf_binary.h"
#include "binary.h"
#include "file.h"

#include <elf.h>
#include <sstream>
#include <stdint.h>

const char *Binary::filename() const
{
  return binary_->filename();
}

Binary::Type Binary::GetType() const
{
  return Type::kUnknown;
}

Binary::Binary(const File *file) : binary_(file) { }

Binary::Type Binary::GetBinaryType(const File *file)
{
  // Check magic numbers to see if it's an ELF file.
  const uint8_t *const buf = file->buffer();
  if (file->size() >= 0x04
      && buf[EI_MAG0] == ELFMAG0
      && buf[EI_MAG1] == ELFMAG1
      && buf[EI_MAG2] == ELFMAG2
      && buf[EI_MAG3] == ELFMAG3) {
    return Binary::Type::kElf;
  }
  // Check magic numbers to see if it's a Portable Executable file.
  if (file->size() >= 0x42
      && buf[0x00] == 'M'
      && buf[0x01] == 'Z'
      && buf[0x40] == 'P'
      && buf[0x41] == 'E') {
    return Binary::Type::kPexe;
  }
  // Check magic numbers to see if it's a MACH file.
  if (file->size() >= 0x04
      && buf[0] == 0XFE
      && buf[1] == 0xED
      && buf[2] == 0xFA
      && buf[3] == 0xCE) {
    return Binary::Type::kMach;
  }
  // Otherwise, unknown file.
  return Binary::Type::kUnknown;
}

Binary *Binary::ReadFromFile(const char *const binary_name)
{
  File *file = new File(binary_name);

  Binary::Type type = GetBinaryType(file);

  switch (type) {
    case Binary::Type::kElf: {
      return ElfBinary::ParseFile(file);
    }
    case Binary::Type::kPexe: // FALLTHROUGH
    case Binary::Type::kMach: // FALLTHROUGH
    case Binary::Type::kUnknown: {
      fprintf(stderr, "Currently only handles ELF format files.\n");
      exit(1);
    }
  }
  return nullptr;
}

std::string Binary::ToString() const
{
  std::stringstream res;
  res << filename() << '\n';
  res << "Unknown binary type\n";
  return res.str();
}
