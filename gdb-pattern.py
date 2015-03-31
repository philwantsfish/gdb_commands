from __future__ import with_statement
import gdb
import subprocess
import re

class GdbPatternCreateCommand(gdb.Command):
    """Usage: pattern_create <number>

A command to create an acyclic pattern. This command generates the same pattern as the default Metasploit pattern. This pattern will start repeating after 20280 characters."""

    def __init__ (self):
      super(GdbPatternCreateCommand, self).__init__ ("pattern_create", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
      print("invoking pattern create command")
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
    return -1

  # Ensure size is 0 < size <= 20280
  if size < 0 or size > 20280:
    pattern_create_usage()
    return -1

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
          


class GdbPatternOffsetCommand (gdb.Command):
    """Command Offset"""

    def __init__ (self):
      super(GdbPatternOffsetCommand, self).__init__ ("pattern_offset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
      print("invoking pattern create command")
  
GdbPatternCreateCommand()
GdbPatternOffsetCommand()
