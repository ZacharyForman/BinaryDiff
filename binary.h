#ifndef BINARY_MATCHER_BINARY_H
#define BINARY_MATCHER_BINARY_H

#include <memory>
#include <string>

class File;

// A type representing a generic binary file.
// This class is subtyped for various types of
// binary, e.g. ELF, Portable Executable, etc.
class Binary {
public:
  // An enumeration representing a subset of the
  // various types of binary that exist.
  enum class Type;

  // Given a file, determines what type of
  // binary that file is.
  // If the file is of unknown type or not an
  // binary file, returns kUnknown.
  static Type GetBinaryType(const File *f);

  // Reads a binary from the given file.
  // If this is impossible (e.g. the file is empty,
  // or otherwise not an binary), returns nullptr.
  static Binary *ReadFromFile(const char *const f);

  // Empty destructor.
  virtual ~Binary();

  // Returns the filename of the underlying File associated
  // with the binary.
  const char *filename() const;

  // Returns the specific type of this binary.
  virtual Type GetType() const;

  // Returns a string that summarises the binary.
  // This may include a string representation of various
  // components of the binary, e.g. section headers and
  // symbol tables.
  virtual std::string ToString() const;

protected:
  // Constructs a Binary from the given file, taking ownership
  // of it.
  Binary(const File *file);

private:
  // The file that this object encapsulates.
  std::unique_ptr<const File> binary_;
};

enum class Binary::Type {
  // Unknown type.
  kUnknown,
  // ELF format.
  kElf,
  // Portable Executable format.
  kPexe,
  // MACH format.
  kMach,
};

#endif // BINARY_MATCHER_BINARY_H
