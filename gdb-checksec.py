from __future__ import with_statement
import gdb
import subprocess
import re

class GdbChecksecCommand (gdb.Command):
    """A GDB command inspired by checksec.sh and PEDA. This command will output the 
exploit mititgations compiled with the binary and each sharedlibrary."""

    def __init__ (self):
      super(GdbChecksecCommand, self).__init__ ("checksec", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
      mods = get_modules()

      headers = ('NX', 'PIE', 'Canary', 'Relro', 'Path')
      f = "| {0: <3} | {1: <3} | {2: <6} | {3: <7} | {4: <10}"
      print(f.format(*headers))
      msaf = ModuleSecurityAttributesFactory()
      for mod in mods:
        msa = msaf.create(mod)
        print(f.format(*msa.attributes()))
   
class ModuleSecurityAttributes:
  def __init__(self, mod_name):
    self.mod_name = mod_name
    self.pie = ""
    self.relro = ""
    self.nx = ""
    self.canary = ""

  def attributes(self):
    return (self.nx, self.pie, self.canary, self.relro, self.mod_name)

class ModuleSecurityAttributesFactory:
  def create(self, mod_name):
    msa = ModuleSecurityAttributes(mod_name)
    readelf_output = str(subprocess.check_output(["readelf", "-W", "-a", mod_name]))

    # Set NX attribute
    msa.nx = "Yes"
    stack = re.search(r"GNU_STACK\s+(?:0x[a-zA-Z0-9]+\s+){5}(RW)(E?)", readelf_output)
    if stack == None or stack.group(2) == "E":
      msa.nx = "No"
  
    # Set PIE attribute
    msa.pie = "No"
    if None != re.search("Type:.*DYN \(", readelf_output):
      msa.pie = "Yes"

    # Set Relro attribute
    msa.relro = "No"
    if None != re.search("GNU_RELRO", readelf_output):
      msa.relro = "Partial"
    if None != re.search("BIND_NOW", readelf_output):
      msa.relro = "Full"

    # Set Canary attribute
    msa.canary = "No"
    if None != re.search("__stack_chk_fail", readelf_output):
      msa.canary = "Yes"
        
    return msa

def readelf_output(mod_name):
  readelf_output = subprocess.check_output(["readelf", "-W", "-a", mod_name])
  return str(readelf_output)
 
def get_modules():
  mods = [] 

  # Get the binary currently being debugged
  inferiors_output = gdb.execute("info inferiors", False, True)
  mobjs = re.findall('\*?\s*(\w+)\s+(\w+ \d+)\s+([^\s]+)', inferiors_output)
  for m in mobjs:
    mods.append(m[2])
  
  # Get the sharedlibrarys
  sharedlibrary_output = gdb.execute("info sharedlibrary", False, True)
  mobjs = re.findall("(0x[a-zA-Z0-9]+)\s+(0x[a-zA-Z0-9]+)\s+(\w+)(\s+\(\*\))?\s+([^\s]+)", sharedlibrary_output)
  for m in mobjs:
    mods.append(m[4])
  return mods
  

GdbChecksecCommand()
