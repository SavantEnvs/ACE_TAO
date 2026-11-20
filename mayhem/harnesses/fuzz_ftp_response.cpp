// ACE INet FTP reply parser (protocols/ace/INet/FTP_Response.cpp), incl. multi-line replies.
#include "fuzz_common.h"
#include "ace/INet/FTP_Response.h"
#include <sstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  std::string s (reinterpret_cast<const char *> (data), size);
  std::istringstream is (s);
  for (int i = 0; i < 64 && is.good (); ++i)
    {
      ACE::FTP::Response r;
      if (!r.read (is))
        break;
      (void) r.status ();
      (void) r.status_type ();
      std::ostringstream os;
      r.write (os);
    }
  return 0;
}
