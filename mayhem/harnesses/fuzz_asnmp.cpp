// ASNMP SNMP PDU decoding (ACE/ASNMP/asnmp/wpdu.cpp, asn1.cpp BER decoder, pdu.cpp, vb.cpp and
// the Oid/OctetStr/address value classes): a received datagram is decoded into a Pdu.
#include "fuzz_common.h"
#include "asnmp/wpdu.h"
#include "asnmp/pdu.h"
#include "asnmp/vb.h"
#include <string.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  // One spare byte so an empty datagram still has a valid (non-null) buffer pointer.
  std::vector<unsigned char> buf (size + 1);
  if (size)
    memcpy (buf.data (), data, size);
  iovec iov;
  iov.iov_base = reinterpret_cast<char *> (buf.data ());
  iov.iov_len = size;
  wpdu w (iov);
  Pdu pdu;
  snmp_version ver;
  if (w.get_pdu (pdu, ver) == 0)
    {
      (void) pdu.to_string ();
      for (int i = 0; i < pdu.get_vb_count (); ++i)
        {
          Vb vb;
          pdu.get_vb (vb, i);
          (void) vb.to_string ();
        }
    }
  return 0;
}
