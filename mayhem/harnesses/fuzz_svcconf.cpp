// svc.conf directive parser (ace/Svc_Conf_Lexer.cpp, Svc_Conf_y.cpp, Parse_Node.cpp,
// Service_Gestalt.cpp, incl. the UTF-8/16/32 encoding detection). Each input runs in its own
// ACE_Service_Gestalt so no service registration survives into the next input.
#include "fuzz_common.h"
#include "ace/Service_Gestalt.h"
#include <string>

// A `dynamic` directive names a shared library and a factory symbol that ACE then dlopen()s and
// calls: that executes code chosen by the config, which svc.conf trusts by design. Mock the
// loader (a libc environment shim, not a change to ACE) so every load fails cleanly and the
// parser and Parse_Node error paths still run.
extern "C" void *dlopen (const char *, int) { return 0; }

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  std::string s (reinterpret_cast<const char *> (data), size);
  ACE_Service_Gestalt g;
  g.process_directive (s.c_str ());
  return 0;
}
