#include "elf_executable.h"
#include "file.h"

#include <stdio.h>
#include <elf.h>

namespace {

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(buf+(offset)))

static uint8_t
ExtractElfHeaderClass(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 4);
}

static uint8_t
ExtractElfHeaderData(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 5);
}

static uint8_t
ExtractElfHeaderShortVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 6);
}

static uint8_t
ExtractElfHeaderOsAbi(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 7);
}

static uint8_t
ExtractElfHeaderAbiVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 8);
}

static uint16_t
ExtractElfHeaderType(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT);
}

static uint16_t
ExtractElfHeaderMachine(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT+2);
}

static uint32_t
ExtractElfHeaderLongVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(32, EI_NIDENT+4);
}

static uint64_t
ExtractElfHeaderEntryPoint(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+8);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+8);
    }
  }
  return -1;
}

static uint64_t
ExtractElfHeaderProgramHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+12);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+16);
    }
  }
  return -1;
}

static uint64_t
ExtractElfHeaderSectionHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+16);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+24);
    }
  }
  return -1;
}

static uint32_t
ExtractElfHeaderFlags(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+20);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+32);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+24);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+36);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderProgramHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+26);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+38);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderProgramHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+28);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+40);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+30);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+42);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+32);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+44);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderNamesIndex(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+34);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+46);
    }
  }
  return -1;
}

static bool
ValidElfHeaderClass(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return true;
    case ELFCLASS64: return true;
  }
  fprintf(stderr, "ELF Header has invalid class\n");
  return false;
}

static bool
ValidElfHeaderData(const uint8_t kData)
{
  switch (kData) {
    case ELFDATA2LSB: return true;
    case ELFDATA2MSB: return true;
  }
  fprintf(stderr, "ELF Header has invalid data type\n");
  return false;
}

static bool
ValidElfHeaderShortVersion(const uint8_t kShortVersion)
{
  switch (kShortVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid short version\n");
  return false;
}

static bool
ValidElfHeaderOsAbi(const uint8_t kOsAbi)
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

static bool
ValidElfHeaderAbiVersion(const uint8_t kAbiVersion)
{
  switch (kAbiVersion) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid ABI version\n");
  return false;
}

static bool
ValidElfHeaderType(const uint16_t kType)
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

static bool
ValidElfHeaderMachine(const uint16_t kMachine)
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

static bool
ValidElfHeaderLongVersion(const uint32_t kLongVersion)
{
  switch (kLongVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid long version\n");
  return false;
}

static bool
ValidElfHeaderEntryPoint(const uint64_t kEntryPoint)
{
  return true;
}

static bool
ValidElfHeaderProgramHeaderOffset(const uint64_t kProgramHeaderOffset)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderOffset(const uint64_t kSectionHeaderOffset)
{
  return true;
}

static bool
ValidElfHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid flags\n");
  return false;
}

static bool
ValidElfHeaderHeaderSize(const uint16_t kHeaderSize)
{
  switch (kHeaderSize) {
    case EI_NIDENT + 36: return true;
    case EI_NIDENT + 48: return true;
  }
  fprintf(stderr, "ELF Header has invalid header size\n");
  return false;
}

static bool
ValidElfHeaderProgramHeaderSize(const uint16_t kProgramHeaderSize)
{
  return true;
}

static bool
ValidElfHeaderProgramHeaderCount(const uint16_t kProgramHeaderCount)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderSize(const uint16_t kSectionHeaderSize)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderCount(const uint16_t kSectionHeaderCount)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderNamesIndex(const uint16_t kSectionHeaderNamesIndex)
{
  return true;
}

static bool
ValidElfHeader(const ElfExecutable::Header *const head)
{
  if (!head) {
    return false;
  }

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

static uint32_t
ExtractElfProgramHeaderType(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint32_t
ExtractElfProgramHeaderFlags(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderOffset(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderVirtualAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderPhysicalAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderFileSize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderMemorySize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfProgramHeaderAlign(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static bool
ValidElfProgramHeaderType(const uint32_t kType)
{
  switch (kType) {
  }
  fprintf(stderr, "ELF Program Header has invalid type\n");
  return false;
}

static bool
ValidElfProgramHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
  }
  fprintf(stderr, "ELF Program Header has invalid flags\n");
  return false;
}

static bool
ValidElfProgramHeaderOffset(const uint64_t kOffset)
{
  switch (kOffset) {
  }
  fprintf(stderr, "ELF Program Header has invalid offset\n");
  return false;
}

static bool
ValidElfProgramHeaderVirtualAddress(const uint64_t kVirtualAddress)
{
  switch (kVirtualAddress) {
  }
  fprintf(stderr, "ELF Program Header has invalid virtual address\n");
  return false;
}

static bool
ValidElfProgramHeaderPhysicalAddress(const uint64_t kPhysicalAddress)
{
  switch (kPhysicalAddress) {
  }
  fprintf(stderr, "ELF Program Header has invalid physical address\n");
  return false;
}

static bool
ValidElfProgramHeaderFileSize(const uint64_t kFileSize)
{
  switch (kFileSize) {
  }
  fprintf(stderr, "ELF Program Header has invalid file size\n");
  return false;
}

static bool
ValidElfProgramHeaderMemorySize(const uint64_t kMemorySize)
{
  switch (kMemorySize) {
  }
  fprintf(stderr, "ELF Program Header has invalid memory size\n");
  return false;
}

static bool
ValidElfProgramHeaderAlign(const uint64_t kAlign)
{
  switch (kAlign) {
  }
  fprintf(stderr, "ELF Program Header has invalid align\n");
  return false;
}

static bool
ValidElfProgramHeader(const ElfExecutable::ProgramHeader &program_header)
{
  if (!ValidElfProgramHeaderType(program_header.kType)) {
    return false;
  }

  if (!ValidElfProgramHeaderFlags(program_header.kFlags)) {
    return false;
  }

  if (!ValidElfProgramHeaderOffset(program_header.kOffset)) {
    return false;
  }

  if (!ValidElfProgramHeaderVirtualAddress(program_header.kVirtualAddress)) {
    return false;
  }

  if (!ValidElfProgramHeaderPhysicalAddress(program_header.kPhysicalAddress)) {
    return false;
  }

  if (!ValidElfProgramHeaderFileSize(program_header.kFileSize)) {
    return false;
  }

  if (!ValidElfProgramHeaderMemorySize(program_header.kMemorySize)) {
    return false;
  }

  if (!ValidElfProgramHeaderAlign(program_header.kAlign)) {
    return false;
  }

  return true;
}

static uint32_t
ExtractElfSectionHeaderName(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint32_t
ExtractElfSectionHeaderType(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderFlags(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderOffset(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderSize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint32_t
ExtractElfSectionHeaderLink(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint32_t
ExtractElfSectionHeaderInfo(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderAddressAlignment(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static uint64_t
ExtractElfSectionHeaderEntrySize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{

}

static bool
ValidElfSectionHeaderName(const uint32_t kName)
{
  switch (kName) {
  }
  fprintf(stderr, "ELF Section Header has invalid name\n");
  return false;
}

static bool
ValidElfSectionHeaderType(const uint32_t kType)
{
  switch (kType) {
  }
  fprintf(stderr, "ELF Section Header has invalid type\n");
  return false;
}

static bool
ValidElfSectionHeaderFlags(const uint64_t kFlags)
{
  switch (kFlags) {
  }
  fprintf(stderr, "ELF Section Header has invalid flags\n");
  return false;
}

static bool
ValidElfSectionHeaderAddress(const uint64_t kAddress)
{
  switch (kAddress) {
  }
  fprintf(stderr, "ELF Section Header has invalid address\n");
  return false;
}

static bool
ValidElfSectionHeaderOffset(const uint64_t kOffset)
{
  switch (kOffset) {
  }
  fprintf(stderr, "ELF Section Header has invalid offset\n");
  return false;
}

static bool
ValidElfSectionHeaderSize(const uint64_t kSize)
{
  switch (kSize) {
  }
  fprintf(stderr, "ELF Section Header has invalid size\n");
  return false;
}

static bool
ValidElfSectionHeaderLink(const uint32_t kLink)
{
  switch (kLink) {
  }
  fprintf(stderr, "ELF Section Header has invalid link\n");
  return false;
}

static bool
ValidElfSectionHeaderInfo(const uint32_t kInfo)
{
  switch (kInfo) {
  }
  fprintf(stderr, "ELF Section Header has invalid info\n");
  return false;
}

static bool
ValidElfSectionHeaderAddressAlignment(const uint64_t kAddressAlignment)
{
  switch (kAddressAlignment) {
  }
  fprintf(stderr, "ELF Section Header has invalid address alignment\n");
  return false;
}

static bool
ValidElfSectionHeaderEntrySize(const uint64_t kEntrySize)
{
  switch (kEntrySize) {
  }
  fprintf(stderr, "ELF Section Header has invalid entry size\n");
  return false;
}

static bool
ValidElfSectionHeader(const ElfExecutable::SectionHeader &header)
{
  if (!ValidElfSectionHeaderName(header.kName)) {
    return false;
  }

  if (!ValidElfSectionHeaderType(header.kType)) {
    return false;
  }

  if (!ValidElfSectionHeaderFlags(header.kFlags)) {
    return false;
  }

  if (!ValidElfSectionHeaderAddress(header.kAddress)) {
    return false;
  }

  if (!ValidElfSectionHeaderOffset(header.kOffset)) {
    return false;
  }

  if (!ValidElfSectionHeaderSize(header.kSize)) {
    return false;
  }

  if (!ValidElfSectionHeaderLink(header.kLink)) {
    return false;
  }

  if (!ValidElfSectionHeaderInfo(header.kInfo)) {
    return false;
  }

  if (!ValidElfSectionHeaderAddressAlignment(header.kAddressAlignment)) {
    return false;
  }

  if (!ValidElfSectionHeaderEntrySize(header.kEntrySize)) {
    return false;
  }

  return true;
}

#undef EXTRACT_ELF_FIELD

static ElfExecutable::Header *ParseElfHeader(const uint8_t *const buf)
{
  return new ElfExecutable::Header {
    ExtractElfHeaderClass(buf),
    ExtractElfHeaderData(buf),
    ExtractElfHeaderShortVersion(buf),
    ExtractElfHeaderOsAbi(buf),
    ExtractElfHeaderAbiVersion(buf),
    ExtractElfHeaderType(buf),
    ExtractElfHeaderMachine(buf),
    ExtractElfHeaderLongVersion(buf),
    ExtractElfHeaderEntryPoint(buf),
    ExtractElfHeaderProgramHeaderOffset(buf),
    ExtractElfHeaderSectionHeaderOffset(buf),
    ExtractElfHeaderFlags(buf),
    ExtractElfHeaderHeaderSize(buf),
    ExtractElfHeaderProgramHeaderSize(buf),
    ExtractElfHeaderProgramHeaderCount(buf),
    ExtractElfHeaderSectionHeaderSize(buf),
    ExtractElfHeaderSectionHeaderCount(buf),
    ExtractElfHeaderSectionHeaderNamesIndex(buf),
  };
}

static std::vector<ElfExecutable::ProgramHeader>
ParseElfProgramHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header)
{
  const uint64_t kOffset = header->kProgramHeaderOffset;
  const uint64_t kSize = header->kProgramHeaderSize;
  uint64_t count = header->kProgramHeaderCount;
  if (!kOffset || !count) {
    return std::vector<ElfExecutable::ProgramHeader>();
  }
  std::vector<ElfExecutable::ProgramHeader> program_headers;

  const uint8_t *program_header = buf + kOffset;

  if (count == PN_XNUM) {
    count = ExtractElfSectionHeaderInfo(program_header, header);
  }

  for (unsigned i = 0; i < count; i++) {
    program_headers.push_back(std::move(ElfExecutable::ProgramHeader{
      ExtractElfProgramHeaderType(program_header + i*kSize, header),
      ExtractElfProgramHeaderFlags(program_header + i*kSize, header),
      ExtractElfProgramHeaderOffset(program_header + i*kSize, header),
      ExtractElfProgramHeaderVirtualAddress(program_header + i*kSize, header),
      ExtractElfProgramHeaderPhysicalAddress(program_header + i*kSize, header),
      ExtractElfProgramHeaderFileSize(program_header + i*kSize, header),
      ExtractElfProgramHeaderMemorySize(program_header + i*kSize, header),
      ExtractElfProgramHeaderAlign(program_header + i*kSize, header)
    }));
  }

  return program_headers;
}

static std::vector<ElfExecutable::SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header)
{
  const uint64_t kOffset = header->kSectionHeaderOffset;
  const uint64_t kSize = header->kSectionHeaderSize;
  uint64_t count = header->kSectionHeaderCount;
  if (!kOffset || !count) {
    return std::vector<ElfExecutable::SectionHeader>();
  }
  std::vector<ElfExecutable::SectionHeader> section_headers;

  const uint8_t *section_header = buf + kOffset;

  if (count == SHN_LORESERVE) {
    count = ExtractElfSectionHeaderSize(section_header, header);
  }

  for (unsigned i = 0; i < count; i++) {
    section_headers.push_back(std::move(ElfExecutable::SectionHeader{
      ExtractElfSectionHeaderName(section_header + i*kSize, header),
      ExtractElfSectionHeaderType(section_header + i*kSize, header),
      ExtractElfSectionHeaderFlags(section_header + i*kSize, header),
      ExtractElfSectionHeaderAddress(section_header + i*kSize, header),
      ExtractElfSectionHeaderOffset(section_header + i*kSize, header),
      ExtractElfSectionHeaderSize(section_header + i*kSize, header),
      ExtractElfSectionHeaderLink(section_header + i*kSize, header),
      ExtractElfSectionHeaderInfo(section_header + i*kSize, header),
      ExtractElfSectionHeaderAddressAlignment(section_header + i*kSize, header),
      ExtractElfSectionHeaderEntrySize(section_header + i*kSize, header),
    }));
  }

  return section_headers;
}

} // namespace

ElfExecutable *ElfExecutable::parse(const File &file)
{
  const uint8_t *const buf = file.buffer();

  std::unique_ptr<Header> header(ParseElfHeader(buf));
  if (!ValidElfHeader(header.get())) {
    return nullptr;
  }

  std::vector<ProgramHeader> program_headers
      = ParseElfProgramHeaders(buf, header.get());

  for (const ProgramHeader &program_header : program_headers) {
    if (!ValidElfProgramHeader(program_header)) {
      return nullptr;
    }
  }

  std::vector<SectionHeader> section_headers
      = ParseElfSectionHeaders(buf, header.get());

  for (const SectionHeader &section_header : section_headers) {
    if (!ValidElfSectionHeader(section_header)) {
      return nullptr;
    }
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
