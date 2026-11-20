// ACE's small text decoders: ACE_CDR::Fixed::from_string (ace/CDR_Base.cpp), ACE_Base64::decode
// (ace/Codecs.cpp), ACE_Utils::UUID::from_string (ace/UUID.cpp) and ACE_ARGV command-line splitting. Byte 0 picks the API.
#include "fuzz_common.h"
#include "ace/CDR_Base.h"
#include "ace/Codecs.h"
#include "ace/UUID.h"
#include "ace/ARGV.h"
#include "ace/SString.h"
#include <stdexcept>
#include <string>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return -1;
  // Every API below takes a NUL-terminated C string.
  std::string s (reinterpret_cast<const char *> (data + 1), size - 1);
  const char *str = s.c_str ();
  switch (data[0] % 4)
    {
    case 0:
      {
        ACE_CDR::Fixed f = ACE_CDR::Fixed::from_string (str);
        char buf[ACE_CDR::Fixed::MAX_STRING_SIZE];
        f.to_string (buf, sizeof buf);
        // Fixed arithmetic reports overflow by throwing std::overflow_error (CDR_Base.cpp).
        try
          {
            ACE_CDR::Fixed g = f * f + f;
            g.to_string (buf, sizeof buf);
          }
        catch (const std::exception &)
          {
          }
        (void) f.fixed_digits ();
        break;
      }
    case 1:
      {
        size_t len = 0;
        ACE_Byte *out = ACE_Base64::decode (reinterpret_cast<const ACE_Byte *> (str), &len);
        delete [] out;
        break;
      }
    case 2:
      {
        ACE_Utils::UUID u;
        u.from_string (ACE_CString (str));
        (void) u.to_string ();
        break;
      }
    default:
      {
        ACE_ARGV argv (str);
        for (int i = 0; i < argv.argc (); ++i)
          (void) argv[i];
        (void) argv.buf ();
        break;
      }
    }
  return 0;
}
