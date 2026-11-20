// ACE configuration import (ace/Configuration_Import_Export.cpp, Configuration.cpp): the input is
// imported as an INI file and as a registry-style file into a fresh in-memory heap configuration.
#include "fuzz_common.h"
#include "ace/Configuration.h"
#include "ace/Configuration_Import_Export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  // Scratch file relative to the working directory (writable under Mayhem; no absolute paths).
  // import_config () takes a file name, so the input has to go through a file.
  std::string path = "ace_cfg_XXXXXX";
  int fd = mkstemp (&path[0]);
  if (fd < 0)
    return 0;
  if (write (fd, data, size) != (ssize_t) size)
    {
      close (fd);
      unlink (path.c_str ());
      return 0;
    }
  close (fd);
  {
    ACE_Configuration_Heap cfg;
    if (cfg.open () == 0)
      {
        ACE_Ini_ImpExp ini (cfg);
        ini.import_config (path.c_str ());
      }
  }
  {
    ACE_Configuration_Heap cfg;
    if (cfg.open () == 0)
      {
        ACE_Registry_ImpExp reg (cfg);
        reg.import_config (path.c_str ());
      }
  }
  unlink (path.c_str ());
  return 0;
}
