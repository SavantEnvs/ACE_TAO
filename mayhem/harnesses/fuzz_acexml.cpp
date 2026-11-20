// ACEXML SAX parser (ACEXML/parser/parser/Parser.cpp, ACEXML/common): prolog, DTD, entities,
// attributes, namespaces and encoding handling, driven from an in-memory character stream.
#include "fuzz_common.h"
#include "ACEXML/common/StrCharStream.h"
#include "ACEXML/common/DefaultHandler.h"
#include "ACEXML/common/InputSource.h"
#include "ACEXML/parser/parser/Parser.h"
#include <string>

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  std::string s (reinterpret_cast<const char *> (data), size);
  ACEXML_StrCharStream *stm = new ACEXML_StrCharStream;
  if (stm->open (s.c_str (), "input.xml") != 0)
    {
      delete stm;
      return 0;
    }
  ACEXML_DefaultHandler handler;
  ACEXML_Parser parser;
  ACEXML_InputSource input (stm);   // takes ownership of stm
  parser.setContentHandler (&handler);
  parser.setDTDHandler (&handler);
  parser.setErrorHandler (&handler);
  parser.setEntityResolver (&handler);
  try
    {
      parser.parse (&input);
    }
  catch (const ACEXML_Exception &)
    {
    }
  return 0;
}
