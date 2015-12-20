#ifndef BINARY_MATCHER_EXECUTABLE_H
#define BINARY_MATCHER_EXECUTABLE_H

#include <memory>
#include <string>

class File;

class Executable {
public:
  enum class Type;

  static Type GetExecutableType(const File *f);
  static Executable *ReadFromFile(const char *const f);

  const char *const filename() const;
  virtual Type GetType() const;
  virtual std::string ToString() const;

protected:
  Executable(const File *file);

private:
  std::unique_ptr<const File> binary_;
};

enum class Executable::Type {
  kUnknown,
  kElf,
  kPexe,
  kMach
};

#endif // BINARY_MATCHER_EXECUTABLE_H
