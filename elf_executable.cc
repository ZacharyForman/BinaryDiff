#include "elf_executable.h"
#include "file.h"

#include <stdio.h>
#include <elf.h>

namespace {

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(file.buffer()+(offset)))

static uint8_t ExtractElfHeaderClass(const File &file)
{
  return EXTRACT_ELF_FIELD(8, 4);
}

static uint8_t ExtractElfHeaderData(const File &file)
{
  return EXTRACT_ELF_FIELD(8, 5);
}

static uint8_t ExtractElfHeaderShortVersion(const File &file)
{
  return EXTRACT_ELF_FIELD(8, 6);
}

static uint8_t ExtractElfHeaderOsAbi(const File &file)
{
  return EXTRACT_ELF_FIELD(8, 7);
}

static uint8_t ExtractElfHeaderAbiVersion(const File &file)
{
  return EXTRACT_ELF_FIELD(8, 8);
}

static uint16_t ExtractElfHeaderType(const File &file)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT);
}

static uint16_t ExtractElfHeaderMachine(const File &file)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT+2);
}

static uint32_t ExtractElfHeaderLongVersion(const File &file)
{
  return EXTRACT_ELF_FIELD(32, EI_NIDENT+4);
}

static uint64_t ExtractElfHeaderEntryPoint(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+8);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+8);
    }
  }
  return -1;
}

static uint64_t ExtractElfHeaderProgramHeaderOffset(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+12);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+16);
    }
  }
  return -1;
}

static uint64_t ExtractElfHeaderSectionHeaderOffset(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+16);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+24);
    }
  }
  return -1;
}

static uint32_t ExtractElfHeaderFlags(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+20);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+32);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderHeaderSize(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+24);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+36);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderProgramHeaderSize(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+26);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+38);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderProgramHeaderCount(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+28);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+40);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderSectionHeaderSize(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+30);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+42);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderSectionHeaderCount(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+32);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+44);
    }
  }
  return -1;
}

static uint16_t ExtractElfHeaderSectionHeaderNamesIndex(const File &file)
{
  switch (ExtractElfHeaderClass(file)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+34);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+46);
    }
  }
  return -1;
}

#undef EXTRACT_ELF_FIELD

static ElfExecutable::Header *ParseElfHeader(const File &file)
{
  return new ElfExecutable::Header {
    ExtractElfHeaderClass(file),
    ExtractElfHeaderData(file),
    ExtractElfHeaderShortVersion(file),
    ExtractElfHeaderOsAbi(file),
    ExtractElfHeaderAbiVersion(file),
    ExtractElfHeaderType(file),
    ExtractElfHeaderMachine(file),
    ExtractElfHeaderLongVersion(file),
    ExtractElfHeaderEntryPoint(file),
    ExtractElfHeaderProgramHeaderOffset(file),
    ExtractElfHeaderSectionHeaderOffset(file),
    ExtractElfHeaderFlags(file),
    ExtractElfHeaderHeaderSize(file),
    ExtractElfHeaderProgramHeaderSize(file),
    ExtractElfHeaderProgramHeaderCount(file),
    ExtractElfHeaderSectionHeaderSize(file),
    ExtractElfHeaderSectionHeaderCount(file),
    ExtractElfHeaderSectionHeaderNamesIndex(file),
  };
}

static bool ValidElfHeaderClass(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return true;
    case ELFCLASS64: return true;
  }
  fprintf(stderr, "ELF Header has invalid class\n");
  return false;
}

static bool ValidElfHeaderData(const uint8_t kData)
{
  switch (kData) {
    case ELFDATA2LSB: return true;
    case ELFDATA2MSB: return true;
  }
  fprintf(stderr, "ELF Header has invalid data type\n");
  return false;
}

static bool ValidElfHeaderShortVersion(const uint8_t kShortVersion)
{
  switch (kShortVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid short version\n");
  return false;
}

static bool ValidElfHeaderOsAbi(const uint8_t kOsAbi)
{
  switch (kOsAbi) {
    case ELFOSABI_SYSV: return true;
    case ELFOSABI_HPUX: return true;
    case ELFOSABI_NETBSD: return true;
    case ELFOSABI_LINUX: return true;
    case ELFOSABI_SOLARIS: return true;
    case ELFOSABI_IRIX: return true;
    case ELFOSABI_FREEBSD: return true;
    case ELFOSABI_TRU64: return true;
    case ELFOSABI_ARM: return true;
    case ELFOSABI_STANDALONE: return true;
  }
  fprintf(stderr, "ELF Header has invalid OS ABI\n");
  return false;
}

static bool ValidElfHeaderAbiVersion(const uint8_t kAbiVersion)
{
  switch (kAbiVersion) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid ABI version\n");
  return false;
}

static bool ValidElfHeaderType(const uint16_t kType)
{
  switch (kType) {
    case ET_REL: return true;
    case ET_EXEC: return true;
    case ET_DYN: return true;
    case ET_CORE: return true;
  }
  fprintf(stderr, "ELF Header has invalid type\n");
  return false;
}

static bool ValidElfHeaderMachine(const uint16_t kMachine)
{
  switch (kMachine) {
    case EM_M32: return true;
    case EM_SPARC: return true;
    case EM_386: return true;
    case EM_68K: return true;
    case EM_88K: return true;
    case EM_860: return true;
    case EM_MIPS: return true;
    case EM_PARISC: return true;
    case EM_SPARC32PLUS: return true;
    case EM_PPC: return true;
    case EM_PPC64: return true;
    case EM_S390: return true;
    case EM_ARM: return true;
    case EM_SH: return true;
    case EM_SPARCV9: return true;
    case EM_IA_64: return true;
    case EM_X86_64: return true;
    case EM_VAX: return true;
  }
  fprintf(stderr, "ELF Header has invalid machine type\n");
  return false;
}

static bool ValidElfHeaderLongVersion(const uint32_t kLongVersion)
{
  switch (kLongVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid long version\n");
  return false;
}

static bool ValidElfHeaderEntryPoint(const uint64_t kEntryPoint)
{
  return true;
}

static bool ValidElfHeaderProgramHeaderOffset(const uint64_t kProgramHeaderOffset)
{
  return true;
}

static bool ValidElfHeaderSectionHeaderOffset(const uint64_t kSectionHeaderOffset)
{
  return true;
}

static bool ValidElfHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid flags\n");
  return false;
}

static bool ValidElfHeaderHeaderSize(const uint16_t kHeaderSize)
{
  switch (kHeaderSize) {
    case EI_NIDENT + 36: return true;
    case EI_NIDENT + 48: return true;
  }
  fprintf(stderr, "ELF Header has invalid header size\n");
  return false;
}

static bool ValidElfHeaderProgramHeaderSize(const uint16_t kProgramHeaderSize)
{
  return true;
}

static bool ValidElfHeaderProgramHeaderCount(const uint16_t kProgramHeaderCount)
{
  return true;
}

static bool ValidElfHeaderSectionHeaderSize(const uint16_t kSectionHeaderSize)
{
  return true;
}

static bool ValidElfHeaderSectionHeaderCount(const uint16_t kSectionHeaderCount)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderNamesIndex(const uint16_t kSectionHeaderNamesIndex)
{
  return true;
}

static bool ValidElfHeader(const ElfExecutable::Header *const head)
{
  if (!ValidElfHeaderClass(head->kClass)) {
    return false;
  }

  if (!ValidElfHeaderData(head->kData)) {
    return false;
  }

  if (!ValidElfHeaderShortVersion(head->kShortVersion)) {
    return false;
  }

  if (!ValidElfHeaderOsAbi(head->kOsAbi)) {
    return false;
  }

  if (!ValidElfHeaderAbiVersion(head->kAbiVersion)) {
    return false;
  }

  if (!ValidElfHeaderType(head->kType)) {
    return false;
  }

  if (!ValidElfHeaderMachine(head->kMachine)) {
    return false;
  }

  if (!ValidElfHeaderLongVersion(head->kLongVersion)) {
    return false;
  }

  if (!ValidElfHeaderEntryPoint(head->kEntryPoint)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderOffset(head->kProgramHeaderOffset)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderOffset(head->kSectionHeaderOffset)) {
    return false;
  }

  if (!ValidElfHeaderFlags(head->kFlags)) {
    return false;
  }

  if (!ValidElfHeaderHeaderSize(head->kHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderSize(head->kProgramHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderCount(head->kProgramHeaderCount)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderSize(head->kSectionHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderCount(head->kSectionHeaderCount)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderNamesIndex(head->kSectionHeaderNamesIndex)) {
    return false;
  }
  return true;
}

static std::vector<ElfExecutable::ProgramHeader>
ParseElfProgramHeaders(const File &file,
                       const ElfExecutable::Header *const header)
{
  return std::vector<ElfExecutable::ProgramHeader>();
}

static std::vector<ElfExecutable::SectionHeader>
ParseElfSectionHeaders(const File &file,
                       const ElfExecutable::Header *const header)
{
  return std::vector<ElfExecutable::SectionHeader>();
}

} // namespace

ElfExecutable *ElfExecutable::parse(const File &file)
{
  printf("Starting to parse %s\n", file.filename());

  std::unique_ptr<Header> header(ParseElfHeader(file));
  if (!ValidElfHeader(header.get())) {
    return nullptr;
  }

  std::vector<ProgramHeader> program_headers
      = ParseElfProgramHeaders(file, header.get());
  std::vector<SectionHeader> section_headers
      = ParseElfSectionHeaders(file, header.get());

  if (!header || !program_headers.size() || !section_headers.size()) {
    return nullptr;
  }

  return new ElfExecutable(file, header.get(),
                           std::move(program_headers),
                           std::move(section_headers));
}

ElfExecutable::ElfExecutable(const File &file,
                             Header *header,
                             std::vector<ProgramHeader> &&program_headers,
                             std::vector<SectionHeader> &&section_headers)
  : Executable(file),
    header_(header),
    program_headers_(program_headers),
    section_headers_(section_headers) { }

Executable::Type ElfExecutable::GetType() const
{
  return Executable::Type::kElf;
}

const ElfExecutable::Header *const ElfExecutable::header()
{
  return header_.get();
}
