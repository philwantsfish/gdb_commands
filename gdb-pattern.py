from __future__ import with_statement
import gdb
import subprocess
import re
import struct
import binascii

class GdbPatternCreateCommand(gdb.Command):
    """Usage: pattern_create <number>

A command to create an acyclic pattern. This command generates the same pattern as the default Metasploit pattern. This pattern will start repeating after 20280 characters."""

    def __init__(self):
      super(GdbPatternCreateCommand, self).__init__ ("pattern_create", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
      print(pattern_create(arg))

def pattern_create_usage():
    print("ERROR: Usage: pattern_create <number>")
    print("       This command supports patterns of size 1 to 20280")


def pattern_create(size="20280"):
  # Make sure size is an integer
  try:
    size = int(size)
  except:
    pattern_create_usage()
    return ""

  # Ensure size is 0 < size <= 20280
  if size < 0 or size > 20280:
    pattern_create_usage()
    return ""

  upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  lower="abcdefghijklmnopqrstuvwxyz"
  number="0123456789"
  
  pattern = ""
  while len(pattern) < size:
    for ch1 in upper:
      for ch2 in lower:
        for ch3 in number:
          pattern += ch1 + ch2 + ch3
          if len(pattern) >= size:
            return pattern[:size]
  return pattern
          


class GdbPatternOffsetCommand(gdb.Command):
    """Usage: pattern_offset <sequence>

A command to get the offset of the sequence into the acyclic pattern genereted by pattern_create."""

    def __init__(self):
      super(GdbPatternOffsetCommand, self).__init__ ("pattern_offset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
      offset = pattern_offset(arg)
      if offset != -1:
        print(offset)
      else:
        print("Not a valid sequence")
  
def pattern_offset(arg):
  ret = -1
  sequence = ""
  full_pattern = pattern_create()
  re_sequence = re.compile("[a-zA-Z0-9]{4}")
  re_address = re.compile("0x[a-zA-Z0-9]{8}")
  re_eip = re.compile("eip")

  if re_sequence.match(arg):
    sequnce = arg
  if re_eip.match(arg):
    # Get the value of eip and set this to arg. Below we will parse out the sequence from
    # an address format
    output = gdb.execute("info registers eip", False, True)
    arg = output.split()[1]
  if re_address.match(arg):
    # Note: [::-1] reverses the string
    sequence = binascii.unhexlify(arg[2:]).decode("ascii")[::-1]

  match = re.search(sequence, full_pattern)
  if match:
    ret = match.start()

  return ret 

def pattern_offset_address(addr):
  ret = -1
  full_pattern = pattern_create()

def pattern_offset_sequence(sequence):
  ret = -1
  full_pattern = pattern_create()
  match = re.search(sequence, full_pattern)
  if match:
    ret = match.start()
  return ret 

class GdbFindMSPCommand(gdb.Command):
  """Usage: findmsp
  
A command to find all occruances of the acyclic pattern generated from pattern_create."""

  def __init__(self):
    super(GdbFindMSPCommand, self).__init__("findmsp", gdb.COMMAND_USER)
    
  def invoke(self, arg, from_tty):
    print("test")


GdbPatternCreateCommand()
GdbPatternOffsetCommand()
GdbFindMSPCommand()
