# GDB commands to aid exploit development

Remember to source each command either in the .gdbinit file or command line.
```
  source /path/to/file/gdb-command.py
```

# checksec

This command will output the status of mitigations in each loaded binary and sharedlibrary. Similar to the *checksec.sh* script.

Example:
```
  (gdb) source gdb-checksec.py
  (gdb) checksec
  | NX  | PIE | Canary | Relro   | Path      
  | Yes | No  | No     | Partial | /home/pwf/projects/gdb-plugins/hello_world
  | Yes | Yes | No     | Partial | /lib64/ld-linux-x86-64.so.2
  | Yes | Yes | Yes    | Partial | /lib/x86_64-linux-gnu/libc.so.6
```

# pattern_create

This command generates an acyclic pattern with a maximum length of 20280. This is the same pattern as the default output from the Metasploit pattern_create.rb tool.

Example:
```
  (gdb) source gdb-pattern.py
  (gdb) pattern_create 250
  Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2A

```
# pattern_offset

This command finds the offset of a sequence in the pattern generated from pattern_create. 

Example:

```
(gdb) pattern_offset 9Ae0
119
(gdb) pattern_offset 0x30654139
119
(gdb) i r $rip
rip            0x30654139	0x30654139
(gdb) pattern_offset rip
119
(gdb)
```
# pattern_find

This commands will find all instances of the pattern in memory. The command will display the location of the pattern, the length, and the type of memory region. The command takes no arguments.

Example:

```
(gdb) r
Starting program: /home/pwf/projects/gdb-plugins/hello_world Aa0Aa1Aa2Aa3A Aa0Aa1 AAAAA

Breakpoint 1, 0x000000000040052d in main ()
(gdb) pattern_find 
| Address        | Length | Region
| 0x7fffffffe080 | 13     | [stack]
| 0x7fffffffe08e | 6      | [stack]
(gdb)
```
