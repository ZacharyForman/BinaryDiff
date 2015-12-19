#include "elf_executable.h"
#include "executable.h"
#include "file.h"

#include <memory>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
  const char *const kBinaryName = argc > 1 ? argv[1] : argv[0];

  File file(kBinaryName);

  Executable::Type type = Executable::GetExecutableType(file);

  std::unique_ptr<Executable> executable;

  switch (type) {
    case Executable::Type::kElf: {
      executable.reset(ElfExecutable::parse(file));
      break;
    }
    case Executable::Type::kPexe: // FALLTHROUGH
    case Executable::Type::kMach: // FALLTHROUGH
    case Executable::Type::kUnknown: {
      fprintf(stderr, "Currently only handles ELF format files.\n");
      exit(1);
    }
  }

  if (!executable) {
    fprintf(stderr, "Could not parse %s successfully\n", kBinaryName);
  }

  return 0;
}
