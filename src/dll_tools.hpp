#pragma once

#include <string>
#include <vector>

bool change_imagebase(const std::string &pe_path, const std::string &output_path, uint64_t new_base);

// Data structure to represent IAT segments
struct IATEntry {
  uint32_t call_addr;
  uint32_t tgt_addr;
  uint16_t ordinal;
  std::string function_name;
  std::string module_name;
};

using IATSegment = std::vector<IATEntry>;

std::vector<IATSegment> load_iat(const std::string &iat_csv_path);

bool create_idt(const std::string &dll_path, const std::string &out_path, const std::vector<IATSegment> &segments);

int dump(const std::string &dllName, const std::string &outName);