// ETCL constraint-language lexer and parser (ace/ETCL/ETCL_l.cpp, ETCL_y.cpp,
// ETCL_Constraint.cpp), the grammar behind the Notification/Trader filters.
#include "fuzz_common.h"
#include "ace/ETCL/ETCL_Interpreter.h"
#include <string>

namespace
{
  class Interp : public ETCL_Interpreter
  {
  public:
    int build (const char *c) { return this->build_tree (c); }
  };
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  std::string s (reinterpret_cast<const char *> (data), size);
  Interp i;
  i.build (s.c_str ());
  return 0;
}
