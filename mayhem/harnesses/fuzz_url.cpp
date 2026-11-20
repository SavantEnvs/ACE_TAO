// ACE INet URL parsing (protocols/ace/INet/URLBase.cpp, HTTP_URL.cpp, FTP_URL.cpp): scheme,
// authority, user info, port, path and query.
#include "fuzz_common.h"
#include "ace/INet/URLBase.h"
#include "ace/INet/HTTP_URL.h"
#include "ace/INet/FTP_URL.h"
#include <memory>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  ACE_CString s (reinterpret_cast<const char *> (data), size);
  {
    ACE::HTTP::URL u;
    if (u.parse (s))
      (void) u.to_string ();
  }
  {
    ACE::FTP::URL f;
    if (f.parse (s))
      (void) f.to_string ();
  }
  std::unique_ptr<ACE::INet::URL_Base> b (ACE::INet::URL_Base::create_from_string (s));
  if (b)
    (void) b->to_string ();
  return 0;
}
