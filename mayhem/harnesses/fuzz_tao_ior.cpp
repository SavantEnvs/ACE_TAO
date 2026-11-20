// TAO stringified object references: CORBA::ORB::string_to_object (TAO/tao/ORB.cpp) on
// "IOR:<hex>" (hex decoding + IOR/profile/tagged-component CDR decoding), "corbaloc:"
// (TAO/tao/CORBALOC_Parser.cpp: address list, protocol/version, object key, IIOP_Profile::
// parse_string_i host/port parsing) and the legacy URL form ("iiop://host:port/key") that falls
// through to TAO_Connector_Registry::make_mprofile.
//
// Allow-list: the other registered IOR parsers do I/O by design, so inputs that select them are
// rejected (-1) before the ORB runs: file:// reads a file (FILE_Parser), corbaname: resolves via a
// remote naming service (CORBANAME_Parser), mcast:// multicasts (MCAST_Parser), http:// fetches a
// URL (HTTP_Parser), DLL: loads a shared library (DLL_Parser). "corbaloc:rir:" is also rejected:
// CORBALOC_Parser::parse_string hands it to ORB::resolve_initial_references (no parsing; may
// start a multicast NameService lookup). The selection is made with TAO's own
// TAO_Parser_Registry::match_parser, so the allow-list matches what string_to_object dispatches on.
#include "fuzz_common.h"
#include "tao/ORB.h"
#include "tao/ORB_Core.h"
#include "tao/Object.h"
#include "tao/Parser_Registry.h"
#include "tao/IOR_Parser.h"
#include "ace/OS_NS_string.h"
#include <string>

namespace
{
  CORBA::ORB_var orb;

  struct OrbInit
  {
    OrbInit ()
    {
      int argc = 1;
      char arg0[] = "fuzz_tao_ior";
      char *argv[] = { arg0, 0 };
      orb = CORBA::ORB_init (argc, argv);
    }
  };
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  static OrbInit init;   // one ORB for the process; string_to_object only reads from it
  // string_to_object takes a NUL-terminated C string.
  std::string s (reinterpret_cast<const char *> (data), size);
  const char *str = s.c_str ();
  TAO_IOR_Parser *parser = orb->orb_core ()->parser_registry ()->match_parser (str);
  if (parser != 0)
    {
      static const char corbaloc[] = "corbaloc:";
      static const char rir[] = "corbaloc:rir:";
      if (ACE_OS::strncmp (str, corbaloc, sizeof corbaloc - 1) != 0
          || ACE_OS::strncmp (str, rir, sizeof rir - 1) == 0)
        return -1;
    }
  try
    {
      CORBA::Object_var o = orb->string_to_object (str);
      if (!CORBA::is_nil (o.in ()))
        {
          // Round-trip the decoded reference: marshals every profile back out.
          CORBA::String_var back = orb->object_to_string (o.in ());
        }
    }
  catch (const CORBA::Exception &)
    {
      // INV_OBJREF / BAD_PARAM / MARSHAL are TAO's documented error path for a bad string.
    }
  return 0;
}
