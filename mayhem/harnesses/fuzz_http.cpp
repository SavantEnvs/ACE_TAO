// ACE INet HTTP message parsing (protocols/ace/INet/HTTP_Response.cpp, HTTP_Request.cpp,
// HTTP_Header.cpp, HeaderBase.cpp): the input is parsed as a response and as a request.
#include "fuzz_common.h"
#include "ace/INet/HTTP_Response.h"
#include "ace/INet/HTTP_Request.h"
#include <sstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  std::string s (reinterpret_cast<const char *> (data), size);
  {
    std::istringstream is (s);
    ACE::HTTP::Response r;
    if (r.read (is))
      {
        (void) r.get_status ().get_status ();
        (void) r.get_content_length ();
        (void) r.has_chunked_transfer_encoding ();
        std::ostringstream os;
        r.write (os);
      }
  }
  {
    std::istringstream is (s);
    ACE::HTTP::Request q;
    if (q.read (is))
      {
        (void) q.get_content_length ();
        std::ostringstream os;
        q.write (os);
      }
  }
  return 0;
}
