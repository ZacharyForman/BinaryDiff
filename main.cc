#include "binary.h"
#include "file.h"

#include <memory>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
  const char *const kBinaryName = argc > 1 ? argv[1] : argv[0];

  std::unique_ptr<Binary>
      binary(Binary::ReadFromFile(kBinaryName));

  if (!binary) {
    fprintf(stderr, "Could not parse %s successfully\n", kBinaryName);
  }

  printf("%s", binary->ToString().c_str());

  return 0;
}
