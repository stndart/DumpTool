#include <LIEF/PE.hpp>

#include <iostream>

#include "dll_tools.hpp"

using namespace std;


// Function to change image base
bool change_imagebase(const string &pe_path,
                      const string &output_path, uint64_t new_base) {
  try {
    // Parse the PE file
    unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(pe_path);

    if (!pe) {
      cerr << "Failed to parse PE file: " << pe_path << endl;
      return false;
    }

    // Change the image base
    pe->optional_header().imagebase(new_base);

    // Write the modified PE
    LIEF::PE::Builder::config_t builder_config;
    // builder_config.imports = true; // Preserve imports

    LIEF::PE::Builder builder(*pe, builder_config);
    builder.build();
    builder.write(output_path);

    return true;
  } catch (const exception &e) {
    cerr << "Error changing image base: " << e.what() << endl;
    return false;
  }
}