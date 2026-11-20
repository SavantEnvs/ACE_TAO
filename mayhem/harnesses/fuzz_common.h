// Shared setup for the ACE fuzz harnesses: initialise ACE once (static builds with
// ACE_HAS_NONSTATIC_OBJECT_MANAGER do not run ACE::init() without ace_main) and keep
// ACE's error logging quiet. Both are set once and never changed by an input.
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>
#include "ace/Init_ACE.h"
#include "ace/Log_Msg.h"
#include <cstring>
#include <new>

// ACE_InputCDR (const char *, size_t, ...) requires its buffer to be aligned to
// ACE_CDR::MAX_ALIGNMENT (ACE/ace/CDR_Stream.h, comment on that constructor): CDR padding is
// computed from the absolute read pointer. Copy the stream into an exactly-sized buffer with that
// alignment, so alignment is relative to the stream start (as in a real GIOP message body) and
// ASan still sees any read past its end.
class AlignedCDRBuffer
{
public:
  AlignedCDRBuffer (const uint8_t *data, size_t size, size_t align)
    : align_ (align),
      buf_ (static_cast<char *> (::operator new (size ? size : 1, std::align_val_t (align))))
  {
    if (size)
      std::memcpy (buf_, data, size);
  }
  ~AlignedCDRBuffer () { ::operator delete (buf_, std::align_val_t (align_)); }
  const char *get () const { return buf_; }
private:
  AlignedCDRBuffer (const AlignedCDRBuffer &) = delete;
  AlignedCDRBuffer &operator= (const AlignedCDRBuffer &) = delete;
  size_t align_;
  char *buf_;
};

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
  ACE::init ();
  ACE_LOG_MSG->priority_mask (0, ACE_Log_Msg::PROCESS);
  return 0;
}
#endif
