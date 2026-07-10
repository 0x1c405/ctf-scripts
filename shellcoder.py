#!/usr/bin/python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

# Requirements:
# 1. Does not contain variables (entire shellcode must be under '.text' in the assembly code)
# 2. Does not refer to direct memory addresses (use calls to labels or rip-relative addresses / push to the Stack and use rsp as the address)
# 3. Does not contain any NULL bytes 00 (use registers that match data size)

file = ELF(sys.argv[1])
shellcode = file.section(".text")
print(shellcode.hex())
print("%d bytes - Found NULL byte" % len(shellcode)) if [i for i in shellcode if i == 0] else print("%d bytes - No NULL bytes" % len(shellcode))
