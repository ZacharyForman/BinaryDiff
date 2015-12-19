#ifndef BINARY_MATCHER_EXECUTABLE_H
#define BINARY_MATCHER_EXECUTABLE_H

class File;

class Executable {
public:
  enum class Type;

  static Type GetExecutableType(const File &f);

  const char *const filename() const;
  virtual Type GetType() const;

protected:
  Executable(const File &file);

private:
  const File &binary_;
};

enum class Executable::Type {
  kUnknown,
  kElf,
  kPexe,
  kMach
};

#endif // BINARY_MATCHER_EXECUTABLE_H
