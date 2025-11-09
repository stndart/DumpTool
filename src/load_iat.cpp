#include <fstream>
#include <iostream>
#include <sstream>

#include "dll_tools.hpp"


using namespace std;


// Function to load IAT from CSV
vector<IATSegment> load_iat(const string &iat_csv_path) {
  vector<IATSegment> segments;
  ifstream file(iat_csv_path);
  string line;

  // Skip header
  getline(file, line);

  IATSegment current_segment;
  string last_module;

  while (getline(file, line)) {
    stringstream ss(line);
    string token;
    IATEntry entry;

    // Parse CSV line - adjust based on your actual CSV format
    getline(ss, token, ','); // Calladdr
    entry.call_addr = stoul(token, nullptr, 16);

    getline(ss, token, ','); // Target addr
    entry.tgt_addr = stoul(token, nullptr, 16);

    getline(ss, token, ','); // Ordinal
    if (!token.empty())
      entry.ordinal = (uint16_t)stoi(token);

    getline(ss, entry.function_name, ',');
    getline(ss, entry.module_name, ',');

    // Handle segment boundaries (when module changes)
    if (!last_module.empty() && last_module != entry.module_name) {
      if (!current_segment.empty()) {
        segments.push_back(current_segment);
        current_segment.clear();
      }
    }

    last_module = entry.module_name;
    current_segment.push_back(entry);
  }

  // Push the last segment
  if (!current_segment.empty()) {
    segments.push_back(current_segment);
  }

  return segments;
}
