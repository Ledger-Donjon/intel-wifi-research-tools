#!/usr/bin/env python3

"""
This scripts interacts with the kernel module "pwn.ko" to enable debug
functions.
"""

import argparse
import os
import re
from pathlib import Path
import sys
import time

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "exploit"))
from exploit_enable_debug import enable_debug

DEBUGFS_IWLMVM = next(Path("/sys/kernel/debug/iwlwifi").glob("*/iwlmvm"))
MEM_PATH = str(DEBUGFS_IWLMVM / "mem")
REG_PATH = str(DEBUGFS_IWLMVM / "prph_reg")

def write_mem(addr, data):
    if addr % 4 != 0 or len(data) % 4 != 0:
        if addr % 4 != 0:
            size = addr % 4
            addr &= 0xfffffffc
            data = read_mem(addr, size) + data
        if len(data) % 4 != 0:
            data += read_mem(addr + len(data), 4 - (len(data) % 4))
        return write_mem(addr, data)

    print(f'[*] writing "{data.hex()}" at {addr:x}')
    fd = os.open(MEM_PATH, os.O_RDWR | os.O_SYNC)
    os.lseek(fd, addr, 0)
    size = len(data)
    for offset in range(0, size, 0x80):
        write_size = min(size-offset, 0x80)
        os.write(fd, data[offset:offset+write_size])
    os.close(fd)

def read_mem(addr, size):
    if addr % 4 != 0 or size % 4 != 0:
        new_addr = addr
        new_size = size
        if new_addr % 4 != 0:
            new_addr = addr & 0xfffffffc
            new_size += addr - new_addr
        if new_size % 4 != 0:
            new_size = (new_size + 4) & 0xfffffffc
        data = read_mem(new_addr, new_size)
        offset = addr - new_addr
        return data[offset:offset+size]

    fd = os.open(MEM_PATH, os.O_RDONLY | os.O_SYNC)
    chunks = []
    try:
        os.lseek(fd, addr, os.SEEK_SET)
        for offset in range(0, size, 0x80):
            read_size = min(0x80, size - offset)
            chunk = os.read(fd, read_size)
            if len(chunk) != read_size:
                raise RuntimeError(f"Truncated read while reading {read_size} bytes")
            chunks.append(chunk)
    finally:
        os.close(fd)

    return b"".join(chunks)

def read_reg(addr):
    #print(f'[*] reading reg {addr:x}')
    fd = os.open(REG_PATH, os.O_RDWR | os.O_SYNC)
    os.lseek(fd, addr, 0)
    os.write(fd, f"{addr:d}\n".encode("ascii"))
    os.lseek(fd, 0, 0)
    data = os.read(fd, 128)
    os.close(fd)
    m = re.match("^Reg 0x([0-9a-f]+): \((0x[0-9a-f]+)\)$", data.decode("ascii"))
    assert m
    addr_ = int(m.group(1), 16)
    assert addr_ == addr
    value = int(m.group(2), 16)
    return value

def write_reg(addr, value):
    print(f'[*] write to reg {addr:x}')
    fd = os.open(REG_PATH, os.O_WRONLY | os.O_SYNC)
    os.lseek(fd, addr, 0)
    os.write(fd, f"{addr:d} {value:d}\n".encode("ascii"))
    os.close(fd)

def lmac_dump_identity_auxreg():
    # dump identity register from lmac in a sysassert
    # write IDENTIY to branchlink2 offset
    write_mem(0x00048B04, b"\x1f\xa1\x6a\x20")
    # nop the branchlink2 value
    write_mem(0x00048B62, b"\xe0\x78\xe0\x78")

def encode_int32(value):
    s = int(value).to_bytes(4, "big")
    s = [ s[1], s[0], s[3], s[2] ]
    return bytes(s)

HOOKED_PTR, HOOKED_FUNCTION = 0x80463708, 0x010108b4

def remove_hook():
    """Restore the function pointer to its original value."""
    write_mem(HOOKED_PTR, int(HOOKED_FUNCTION).to_bytes(4, "little"))

def write_debugger_payload(hooked_ptr, hooked_function, mac):
    shellcode_addr = {
        "lmac": 0x0004ad00,
        "umac": 0x0102c0a0,
    }[mac]

    current_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(current_dir, "prologue.bin"), "rb") as fp:
        prologue = fp.read()

    with open(os.path.join(current_dir, f"payload-{mac}.bin"), "rb") as fp:
        payload = fp.read()

    # Replace the 0xdeadbeef pattern in the payload with hooked_function. Once
    # the debugger function returns, this function is eventually called.
    shellcode = prologue + payload
    shellcode = shellcode.replace(encode_int32(0xdeadbeef), encode_int32(hooked_function), 1)

    # write shellcode to memory
    write_mem(shellcode_addr, shellcode)

    # ensure shellcode was successfully written
    data = read_mem(shellcode_addr, len(shellcode))
    assert data == shellcode

    # replace the hooked pointer with the shellcode address
    write_mem(hooked_ptr, int(shellcode_addr).to_bytes(4, "little"))

def test_debugger(mac):
    """
    Let the debugger stub executes commands in a loop. Once the debugger function
    returns, the original function is called.

    It is meant to be called after launching ./debugger.py
    """
    write_debugger_payload(HOOKED_PTR, HOOKED_FUNCTION, mac)

def qemu_emulation(hooked_ptr, mac):
    """
    Let an external debugger emulate the hooked function.
    It is meant to be called after launching:
      ./build/qemu-arc -singlestep -pc 0x000172b0 -plugin ./build/contrib/plugins/libhook-mem.so /tmp/iwlwifi-8000C-34.ucode.regular.elf
    """

    null_sub = {
        "lmac": 0x00036140,
        "umac": 0xc008bb78,
    }[mac]
    write_debugger_payload(hooked_ptr, null_sub, mac)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="call the target function once the debugger returns")
    parser.add_argument("--emulation", action="store_true", help="call the debugger stubs")
    parser.add_argument("--hooked-ptr", type=lambda x: int(x, 0), help="hooked pointer address")
    parser.add_argument("--mac", default="lmac", choices=["lmac", "umac"])
    args = parser.parse_args()

    enable_debug()

    if args.debug:
        print("[*] debugger mode")
        test_debugger(args.mac)
    elif args.emulation:
        if not hasattr(args, "hooked_ptr"):
            print("[-] --hooked-ptr is mandatory in emulation mode")
            sys.exit(1)
        print(f"[*] emulation mode (hooked ptr: {args.hooked_ptr:x})")
        qemu_emulation(args.hooked_ptr, args.mac)
