// ACE_InputCDR decoder (ace/CDR_Stream.cpp, CDR_Base.cpp): byte 0 picks byte order and GIOP
// minor version; the rest is a CDR stream that is read as a sequence of (opcode, value) items.
// Opcodes (op % 32): 0-9 strings/wstrings/Fixed, 10-19 arrays, 20-29 scalars, 30 skip_<scalar>,
// 31 Fixed arithmetic on two decoded values.
#include "fuzz_common.h"
#include "ace/CDR_Stream.h"
#include "ace/SString.h"
#include <stdexcept>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 1)
    return -1;
  const int byte_order = data[0] & 1;
  const ACE_CDR::Octet minor = (data[0] >> 1) % 3;
  AlignedCDRBuffer stream (data + 1, size - 1, ACE_CDR::MAX_ALIGNMENT);
  ACE_InputCDR cdr (stream.get (), size - 1, byte_order, 1, minor);
  for (int iter = 0; iter < 256 && cdr.good_bit (); ++iter)
    {
      ACE_CDR::Octet op = 0;
      if (!cdr.read_octet (op))
        break;
      switch (op % 32)
        {
        case 0: { ACE_CDR::Char *s = 0; if (cdr.read_string (s)) delete [] s; break; }
        case 1: { ACE_CDR::WChar *s = 0; if (cdr.read_wstring (s)) delete [] s; break; }
        case 2: { std::string s; cdr.read_string (s); break; }
        case 3: { std::wstring s; cdr.read_wstring (s); break; }
        case 4: { ACE_CString s; cdr.read_string (s); break; }
        case 5: { ACE_CDR::Fixed f; if (cdr.read_fixed (f)) { char buf[ACE_CDR::Fixed::MAX_STRING_SIZE]; f.to_string (buf, sizeof buf);
                  // Fixed -> LongLong is a narrowing conversion, like double -> int: a caller converts
                  // only values whose integer part fits (at most 18 integer digits).
                  if (f.fixed_digits () - f.fixed_scale () <= 18) (void) static_cast<ACE_CDR::LongLong> (f);
                  (void) static_cast<ACE_CDR::LongDouble> (f);
                  f.round (f.fixed_digits () / 2).to_string (buf, sizeof buf); f.truncate (1).to_string (buf, sizeof buf); } break; }
        case 6: cdr.skip_string (); break;
        case 7: cdr.skip_wstring (); break;
        case 8: { ACE_CDR::ULong bound = 0; if (!cdr.read_ulong (bound)) break;
                  ACE_CDR::Char *s = 0;
                  if (cdr >> ACE_InputCDR::to_string (s, bound)) delete [] s; break; }
        case 9: { ACE_CDR::ULong bound = 0; if (!cdr.read_ulong (bound)) break;
                  ACE_CDR::WChar *s = 0;
                  if (cdr >> ACE_InputCDR::to_wstring (s, bound)) delete [] s; break; }
        case 20: { ACE_CDR::WChar w; cdr.read_wchar (w); break; }
        case 21: cdr.skip_wchar (); break;
        case 22: { ACE_CDR::Boolean b; cdr.read_boolean (b); break; }
        case 23: { ACE_CDR::Char c; cdr.read_char (c); break; }
        case 24: { ACE_CDR::Short v; cdr.read_short (v); break; }
        case 25: { ACE_CDR::ULong v; cdr.read_ulong (v); break; }
        case 26: { ACE_CDR::ULongLong v; cdr.read_ulonglong (v); break; }
        case 27: { ACE_CDR::Float v; cdr.read_float (v); break; }
        case 28: { ACE_CDR::Double v; cdr.read_double (v); break; }
        case 29: { ACE_CDR::LongDouble v; cdr.read_longdouble (v); break; }
        case 30:
          {
            ACE_CDR::Octet k = 0;
            if (!cdr.read_octet (k)) break;
            switch (k % 8)
              {
              case 0: cdr.skip_boolean (); break;
              case 1: cdr.skip_char (); break;
              case 2: cdr.skip_short (); break;
              case 3: cdr.skip_long (); break;
              case 4: cdr.skip_longlong (); break;
              case 5: cdr.skip_float (); break;
              case 6: cdr.skip_double (); break;
              default: cdr.skip_longdouble (); break;
              }
            break;
          }
        case 31:
          {
            ACE_CDR::Fixed f, g;
            if (!cdr.read_fixed (f) || !cdr.read_fixed (g)) break;
            char buf[ACE_CDR::Fixed::MAX_STRING_SIZE];
            // Fixed arithmetic reports a result over 31 integer digits by throwing
            // std::overflow_error (ACE/ace/CDR_Base.cpp, operator+= / *= / /=): that is the API's
            // error path, which a caller handles, so each operation catches it.
            try { ACE_CDR::Fixed r = f + g; r.to_string (buf, sizeof buf); } catch (const std::overflow_error &) {}
            try { ACE_CDR::Fixed r = f - g; r.to_string (buf, sizeof buf); } catch (const std::overflow_error &) {}
            try { ACE_CDR::Fixed r = f * g; r.to_string (buf, sizeof buf); } catch (const std::overflow_error &) {}
            if (!!g)  // caller contract: no divide by zero
              try { ACE_CDR::Fixed r = f / g; r.to_string (buf, sizeof buf); } catch (const std::overflow_error &) {}
            (void) (f < g); (void) (f == g);
            try { ++f; --g; } catch (const std::overflow_error &) {}
            break;
          }
        default:
          {
            ACE_CDR::ULong n = 0;
            if (!cdr.read_ulong (n)) break;
            n %= 512;
            std::vector<ACE_CDR::LongDouble> buf (n + 1);
            void *p = buf.data ();
            switch (op % 32)
              {
              case 10: cdr.read_boolean_array (static_cast<ACE_CDR::Boolean *> (p), n); break;
              case 11: cdr.read_char_array (static_cast<ACE_CDR::Char *> (p), n); break;
              case 12: cdr.read_wchar_array (static_cast<ACE_CDR::WChar *> (p), n); break;
              case 13: cdr.read_short_array (static_cast<ACE_CDR::Short *> (p), n); break;
              case 14: cdr.read_long_array (static_cast<ACE_CDR::Long *> (p), n); break;
              case 15: cdr.read_longlong_array (static_cast<ACE_CDR::LongLong *> (p), n); break;
              case 16: cdr.read_float_array (static_cast<ACE_CDR::Float *> (p), n); break;
              case 17: cdr.read_double_array (static_cast<ACE_CDR::Double *> (p), n); break;
              case 18: cdr.read_longdouble_array (static_cast<ACE_CDR::LongDouble *> (p), n); break;
              default: cdr.skip_bytes (n); break;
              }
          }
        }
    }
  return 0;
}
