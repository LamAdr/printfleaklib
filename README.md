# printfleaklib
Simple linux CTF tool used to manage printf format string vulnerability leaks using pwnlib.

Sends the target process a formatted string, compares the values leaked with mapped addresses from /proc/[pid]/maps and return their offsets.
For values pointing to stack addresses, returns the offset from the return address's address to help it's overwriting.
gdb is used to find the return address. It logs it via the gdb.txt file that you will find in $PWD.

I install it this way:
$ 

Compile demo.c with 'gcc demo.c -o demo' and run demo.py against it.

I don't doubt that anyone can improve this code. Please do so if you feel like it.

This is a toy to play games. Use ethically.
