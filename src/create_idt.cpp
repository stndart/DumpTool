#include <LIEF/PE.hpp>

#include <iostream>

#include "dll_tools.hpp"

using namespace std;

// Function to create Import Directory Table (IDT)
bool create_idt(const string &dll_path, const string &out_path,
                const vector<IATSegment> &segments) {
  try {
    // Parse the PE file[citation:1]
    unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(dll_path);

    if (!pe) {
      cerr << "Failed to parse PE file: " << dll_path << endl;
      return false;
    }

    // Remove all existing imports[citation:1]
    pe->remove_all_imports();

    // Set entry point (adjust as needed)
    pe->optional_header().addressof_entrypoint(0x13903);

    // Rebuild imports from segments
    for (const auto &segment : segments) {
      if (segment.empty())
        continue;

      const string &dll_name = segment[0].module_name;
      if (dll_name.empty())
        continue;

      // Add new import library[citation:1]
      LIEF::PE::Import &import_lib = pe->add_import(dll_name);
      std::cout << "Adding import " << dll_name << "\n";

      for (const auto &entry : segment) {
        if (entry.function_name.find("Ordinal#") == 0) {
          // Handle ordinal imports
          // Create import by ordinal - LIEF handles this internally
          //   import_lib.add_entry(entry.ordinal);
        } else {
          // Handle named imports[citation:1]
          auto &nentry = import_lib.add_entry(entry.function_name);
          nentry.iat_address(entry.call_addr); // just for LIEF checks
        }
      }
      import_lib.import_address_table_rva(segment[0].call_addr);
    }

    // Build and write with imports configuration[citation:1]
    LIEF::PE::Builder::config_t builder_config;
    builder_config.imports = true;

    LIEF::PE::Builder builder(*pe, builder_config);
    builder.build();
    builder.write(out_path);

    return true;
  } catch (const exception &e) {
    cerr << "Error creating IDT: " << e.what() << endl;
    return false;
  }
}