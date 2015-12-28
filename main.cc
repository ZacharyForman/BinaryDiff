#include "executable.h"
#include "file.h"

#include <memory>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
  const char *const kBinaryName = argc > 1 ? argv[1] : argv[0];

  std::unique_ptr<Executable>
      executable(Executable::ReadFromFile(kBinaryName));

  if (!executable) {
    fprintf(stderr, "Could not parse %s successfully\n", kBinaryName);
  }

  printf("%s", executable->ToString().c_str());

  return 0;
}
