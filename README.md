# printfleaklib
Simple CTF tool used to manage printf format string vulnerability leaks.

Compares the values leaked with mapped addresses from /proc/[pid]/maps and return their offsets.
For values pointing to stack addresses, returns the offset from the return address's address to help it's overwriting.
gdb is used to find the return address. It logs it via gdb.txt file that you will find in $PWD.

Compile demo.c with 'gcc demo.c -o demo' and run demo.py against it.

I don't doubt that anyone can improve this code. Please do so if you feel like it.

Please use ethically.
