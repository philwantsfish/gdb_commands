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
  sequence = None
  full_pattern = pattern_create()
  re_sequence = re.compile("[a-zA-Z0-9]{4}")
  re_address = re.compile("0x[a-zA-Z0-9]{8}")
  re_eip = re.compile("eip")

  if re_sequence.match(arg):
    sequence = arg
  if arg in registers():
    # Get the value of the register and set this to arg. Below we will parse out the sequence from
    # an address format
    command = "i r {:s}".format(arg)
    output = gdb.execute(command, False, True)
    arg = output.split()[1]
  if re_address.match(arg):
    # Note: [::-1] reverses the string
    sequence = binascii.unhexlify(arg[2:]).decode("ascii")[::-1]

  if sequence != None:
    match = re.search(sequence, full_pattern)
    if match:
      ret = match.start()

  return ret 

def registers():
  output = gdb.execute("i r", False, True)
  lines = output.splitlines()
  registers = []
  for line in lines:
    registers.append(line.split()[0])
  return registers

class GdbPatternFindCommand(gdb.Command):
  """Usage: pattern_find
  
A command to find all occruances of the acyclic pattern generated from pattern_create."""

  def __init__(self):
    super(GdbPatternFindCommand, self).__init__("pattern_find", gdb.COMMAND_USER)
    
  def invoke(self, arg, from_tty):
    # We will be changing the "print elements" variable. Store current setting so we can
    # rever it
    print_elements = get_option_print_elements()
    set_option_print_elements(20280)

    # Return an array of results containing : Address, Length, Region
    results = []
    seq_start = "0x41306141"
    full_pattern = pattern_create()

    # Search each region of memory for the start of the pattern
    mapping = info_mapping()
    for region in mapping:
      # Seach for Aa0A in all regions of memory
      matches = search_region(region, seq_start)
      if len(matches) > 0:
        for m in matches:
          results.append([m, 'unknown', region[4]])

    # Get the length of each pattern
    for r in results:
      command = "x/s {:s}".format(r[0])
      seq = gdb.execute(command, False, True).split()[1][1:-1]
      pattern_len = 0
      while(pattern_len < 20280 and pattern_len < len(seq) and full_pattern[pattern_len] == seq[pattern_len]):
        pattern_len += 1
      r[1] = pattern_len

    # Restore the "print elements" varaible
    set_option_print_elements(print_elements) 


    # Get the size of the address column
    address_column_len = 0 
    for addr in results:
      if len(addr[0]) > address_column_len:
        address_column_len = len(addr[0])

    # Print the data
    f = "| {0: <" + str(address_column_len)  + "} | {1: <6} | {2: <6}"
    headers = ('Address', 'Length', 'Region')
    print(f.format(*headers))
    for r in results:
      print(f.format(*r))


def get_option_print_elements():
  output = gdb.execute("show print elements", False, True)
  num = int(output.split()[-1][:-1])
  return num

def set_option_print_elements(num):
  command = "set print elements {:d}".format(num)
  gdb.execute(command, False, True)
  

# Search memory for a word of data. Returns an array of address that match.
def search_region(region, data):
    command = "find /w {:s}, +{:s}, {:s}".format(region[0], region[2], data)
    output = gdb.execute(command, False, True)
    numfound = int(gdb.execute("print $numfound", False, True).split()[2])
    if numfound > 0:
      return output.splitlines()[:-1] 
    return []

# This function returns a list of tuples for each region of mapped memory
# Tuple contains: (start_addr, end_addr, size, offset, objfile)
# Thought: Should this data be stored in a class with convenience functions?
def info_mapping():
  mapping = gdb.execute("info proc mapping", False, True)
  map_list = []
  for line in mapping.splitlines()[4:]:
    map_list.append(line.split())
  return map_list

GdbPatternCreateCommand()
GdbPatternOffsetCommand()
GdbPatternFindCommand()
