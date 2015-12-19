#ifndef BINARY_MATCHER_FILE_H
#define BINARY_MATCHER_FILE_H

#include <stddef.h>
#include <stdint.h>

class File {
public:
  File(const char *const filename);
  ~File();
  const char *const filename() const { return filename_; }
  const uint8_t *buffer() const { return buf_; }
  const size_t size() const { return size_; }
private:
  int fd_;
  const char *const filename_;
  uint8_t *buf_;
  size_t size_;
};

#endif // BINARY_MATCHER_FILE_H
