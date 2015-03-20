#GDB Checksec:

Remember to source the command in your gdbinit file. *source /path/gdb-checksec.py*
Type *checksec* to view output.
Example:
```
  (gdb) checksec
  | NX  | PIE | Canary | Relro   | Path      
  | Yes | No  | No     | Partial | /home/pwf/projects/gdb-plugins/hello_world
  | Yes | Yes | No     | Partial | /lib64/ld-linux-x86-64.so.2
  | Yes | Yes | Yes    | Partial | /lib/x86_64-linux-gnu/libc.so.6
```
