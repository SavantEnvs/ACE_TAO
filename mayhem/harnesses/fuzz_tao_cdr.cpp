// TAO CDR demarshaling (TAO/tao/CDR.cpp + CDR.inl bounded-string operators,
// tao/AnyTypeCode TypeCode_CDR_Extraction.cpp, Any_Unknown_IDL_Type / skip.cpp, and object
// reference decoding: IOR, profiles and tagged components in tao/Object.cpp, MProfile,
// IIOP_Profile). Byte 0 picks byte order and GIOP minor version; the rest is a CDR stream read
// as a sequence of (opcode, value) items, as a GIOP request/reply body would be.
#include "fuzz_common.h"
#include "tao/ORB.h"
#include "tao/ORB_Core.h"
#include "tao/CDR.h"
#include "tao/Object.h"
#include "tao/AnyTypeCode/Any.h"
#include "tao/AnyTypeCode/TypeCode.h"
#include "tao/AnyTypeCode/AnyTypeCode_Adapter_Impl.h"
#include <string>

namespace
{
  CORBA::ORB_var orb;
  // Pull the AnyTypeCode library's static initializer into the static link.
  int const anytc_init = TAO_AnyTypeCode_Adapter_Impl::Initializer ();
}


namespace
{
  struct OrbInit
  {
    OrbInit ()
    {
      int argc = 1;
      char arg0[] = "fuzz_tao_cdr";
      char *argv[] = { arg0, 0 };
      orb = CORBA::ORB_init (argc, argv);
    }
  };
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static OrbInit init;   // one ORB for the process; inputs only read from it
  (void) anytc_init;
  if (size < 1)
    return -1;
  const int byte_order = data[0] & 1;
  const ACE_CDR::Octet minor = (data[0] >> 1) % 3;
  AlignedCDRBuffer stream (data + 1, size - 1, ACE_CDR::MAX_ALIGNMENT);
  TAO_InputCDR cdr (stream.get (), size - 1, byte_order, 1, minor, orb->orb_core ());
  try
    {
      for (int iter = 0; iter < 64 && cdr.good_bit (); ++iter)
        {
          CORBA::Octet op = 0;
          if (!cdr.read_octet (op))
            break;
          switch (op % 8)
            {
            case 0: { CORBA::Any a; cdr >> a; break; }
            case 1: { CORBA::TypeCode_ptr tc = CORBA::TypeCode::_nil ();
                      if (cdr >> tc) CORBA::release (tc); break; }
            case 2: { CORBA::Object_ptr o = CORBA::Object::_nil ();
                      if (cdr >> o) CORBA::release (o); break; }
            case 3: { CORBA::ULong b = 0; if (!(cdr >> b)) break; CORBA::Char *s = 0;
                      if (cdr >> ACE_InputCDR::to_string (s, b)) CORBA::string_free (s); break; }
            case 4: { CORBA::ULong b = 0; if (!(cdr >> b)) break; CORBA::WChar *s = 0;
                      if (cdr >> ACE_InputCDR::to_wstring (s, b)) CORBA::wstring_free (s); break; }
            case 5: { CORBA::ULong b = 0; if (!(cdr >> b)) break; std::string s;
                      cdr >> ACE_InputCDR::to_std_string (s, b); break; }
            case 6: { CORBA::ULong b = 0; if (!(cdr >> b)) break; std::wstring s;
                      cdr >> ACE_InputCDR::to_std_wstring (s, b); break; }
            default: { CORBA::Any a; if (cdr >> a) { CORBA::TypeCode_var t = a.type ();
                       (void) t->kind (); } break; }
            }
        }
    }
  catch (const CORBA::Exception &)
    {
      // CORBA system exceptions (MARSHAL, BAD_PARAM, ...) are TAO's documented error path.
    }
  return 0;
}
