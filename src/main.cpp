#include "dll_tools.hpp"

#include <iostream>

int main()
{
    const std::string origName = "NeoMon.dll";
    const std::string ibName = "NeoMon_ib.dll";
    const std::string dumpName = "NeoMon_dump.dll";
    const std::string outName = "NeoMon_patched.dll";
    const std::string iatPath = "iat.csv";

    change_imagebase(origName, ibName, 0x10800000);
    dump(ibName, dumpName);

    
    auto iat_segments = load_iat(iatPath);
    std::cout << "Loaded " << iat_segments.size() << " segments\n";
    create_idt(dumpName, outName, iat_segments);

    return 0;
}