#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Helper to interact with iwlwifi chip through debugfs"""
import argparse
import os
from pathlib import Path
import re
import time
from typing import List, Optional
import sys


class WifiDebug:
    """Helper class for iwlwifi debugfs interface"""

    def __init__(self, debugfs_path: Optional[Path] = None) -> None:
        self.fd_mem: Optional[int] = None
        self.fd_prph_reg: Optional[int] = None
        if debugfs_path:
            self.debugfs_path: Path = debugfs_path
        else:
            self.debugfs_path = next(Path("/sys/kernel/debug/iwlwifi").glob("*/"))
        # print(f"Using device path: {self.debugfs_path}")

        self.mem_path = self.debugfs_path / "iwlmvm" / "mem"
        self.prph_reg_path = self.debugfs_path / "iwlmvm" / "prph_reg"
        self.fw_ver_path = self.debugfs_path / "iwlmvm" / "fw_ver"

    def __del__(self) -> None:
        if self.fd_mem is not None:
            os.close(self.fd_mem)
            self.fd_mem = None
        if self.fd_prph_reg is not None:
            os.close(self.fd_prph_reg)
            self.fd_prph_reg = None

    def get_fw_ver(self) -> str:
        """Return the content of fw_ver"""
        with self.fw_ver_path.open("r") as fd:
            return fd.read()

    def open_mem(self) -> None:
        """Open the memory interface"""
        if self.fd_mem is not None:
            os.close(self.fd_mem)
            self.fd_mem = None
        self.fd_mem = os.open(self.mem_path, os.O_RDWR | os.O_SYNC)

    def open_prph_reg(self) -> None:
        """Open the peripheral register interface"""
        if self.fd_prph_reg is not None:
            os.close(self.fd_prph_reg)
            self.fd_prph_reg = None
        self.fd_prph_reg = os.open(self.prph_reg_path, os.O_RDWR | os.O_SYNC)

    def read(self, addr: int, size: int) -> bytes:
        """Read memory using iwlmvm/mem file

        usage: ./iwldebug.py read 0xc0080000

        This relies on DEBUG_GROUP/UMAC_RD_WR for addresses >= 0x01000000 and
        DEBUG_GROUP/LMAC_RD_WR for lower addresses.
        https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/mvm/debugfs.c#L1799 :
            hcmd.id = iwl_cmd_id(*ppos >> 24 ? UMAC_RD_WR : LMAC_RD_WR,
                         DEBUG_GROUP, 0);
            cmd.op = cpu_to_le32(DEBUG_MEM_OP_READ);
            cmd.addr = cpu_to_le32(*ppos - delta);
            cmd.len = cpu_to_le32(min(ALIGN(count + delta, 4) / 4,
                          (size_t)DEBUG_MEM_MAX_SIZE_DWORDS));
            ret = iwl_mvm_send_cmd(mvm, &hcmd);
        """
        assert self.fd_mem is not None
        os.lseek(self.fd_mem, addr, os.SEEK_SET)
        chunks: List[bytes] = []
        for offset in range(0, size, 0x80):
            read_size = min(0x80, size - offset)
            try:
                chunk = os.read(self.fd_mem, read_size)
            except OSError:
                total_read_size = sum(len(x) for x in chunks)
                last_addr = addr + total_read_size
                print(
                    f"Error occurred after reading {total_read_size} bytes from {addr:#x} to {last_addr:#x}",
                    file=sys.stderr,
                )
                raise
            if len(chunk) != read_size:
                raise RuntimeError(f"Truncated read while reading {read_size} bytes")
            chunks.append(chunk)

        return b"".join(chunks)

    def read_u8(self, addr: int) -> int:
        """Read a 8-bit integer"""
        return int.from_bytes(self.read(addr, 1), "little")

    def read_u32(self, addr: int) -> int:
        """Read a 32-bit integer"""
        return int.from_bytes(self.read(addr, 4), "little")

    def read_u64(self, addr: int) -> int:
        """Read a 64-bit integer"""
        return int.from_bytes(self.read(addr, 8), "little")

    def write(self, addr: int, data: bytes) -> None:
        """Write memory using iwlmvm/mem file

        usage: ./iwldebug.py write 0xc0400070 48656c6c6f000000
        (to write "Hello" to 0x000000f0)

        This relies on DEBUG_GROUP/UMAC_RD_WR for addresses >= 0x01000000 and
        DEBUG_GROUP/LMAC_RD_WR for lower addresses, with operation
        DEBUG_MEM_OP_WRITE=1 for 32-bit words writing or DEBUG_MEM_OP_WRITE_BYTES=2
        for byte-granularity writing, in:

        struct iwl_dbg_mem_access_cmd {
            __le32 op;
            __le32 addr;
            __le32 len;
            __le32 data[];
        }

        To write several bytes, the Linux driver enforces a 4-byte alignment of
        the data.
        """
        # Split unaligned writes
        if len(data) >= 4 and (addr & 3) != 0:
            needed_padding = 4 - (addr & 3)
            self.write(addr, data[:needed_padding])
            addr += needed_padding
            data = data[needed_padding:]
            assert (addr & 3) == 0

        # Split writes with unaligned end
        if len(data) >= 4 and (len(data) & 3) != 0:
            aligned_write_size = len(data) & ~3
            self.write(addr, data[:aligned_write_size])
            addr += aligned_write_size
            data = data[aligned_write_size:]
            assert (addr & 3) == 0
            assert 1 <= len(data) <= 3

        # Split writes with more than 128 bytes
        if len(data) > 0x80:
            for offset in range(0, len(data), 0x80):
                write_size = min(0x80, len(data) - offset)
                self.write(addr + offset, data[offset:offset + write_size])
            return

        assert self.fd_mem is not None
        os.lseek(self.fd_mem, addr, os.SEEK_SET)
        try:
            written_size = os.write(self.fd_mem, data)
        except Exception:
            print(f"Failed to write {len(data)} bytes to {addr:#010x} ({data.hex()})", file=sys.stderr)
            raise
        if written_size != len(data):
            raise RuntimeError(f"Truncated write at addr {addr:#x}: {written_size}/{len(data)}")

    def write_u32(self, addr: int, value: int) -> None:
        """Write a 32-bit integer"""
        self.write(addr, value.to_bytes(4, "little"))

    def read_prph_reg(self, addr: int) -> int:
        """Read prph registers

        Usage: ./iwldebug.py reg 0xA00000

        Registers are defined in
        https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/iwl-prph.h
        For example:

            // Program Counter registers!
            #define UREG_UMAC_CURRENT_PC    0xa05c18
            #define UREG_LMAC1_CURRENT_PC   0xa05c1c
            #define UREG_LMAC2_CURRENT_PC   0xa05c20

            // Status used when booting the firmware
            #define SB_CPU_1_STATUS         0xA01E30
            #define SB_CPU_2_STATUS         0xA01E34
            #define UMAG_SB_CPU_1_STATUS    0xA038C0
            #define UMAG_SB_CPU_2_STATUS    0xA038C4
            #define UMAG_GEN_HW_STATUS      0xA038C8

            // Oscillator clock
            #define OSC_CLK         (0xa04068) // triggers a NMI_INTERRUPT_WDG

        Implementation:

        https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/mvm/debugfs.c#L1547
            iwl_dbgfs_prph_reg_write:
                args = sscanf(buf, "%i %i", &mvm->dbgfs_prph_reg_addr, &value);
            iwl_dbgfs_prph_reg_read:
                scnprintf(buf + pos, bufsz - pos, "Reg 0x%x: (0x%x)\n",
                    mvm->dbgfs_prph_reg_addr,
                    iwl_read_prph(mvm->trans, mvm->dbgfs_prph_reg_addr));

        https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/iwl-io.c#L140
            u32 iwl_read_prph(struct iwl_trans *trans, u32 ofs)
            {
                u32 val = 0x5a5a5a5a;
                if (iwl_trans_grab_nic_access(trans, &flags)) {
                    val = iwl_read_prph_no_grab(trans, ofs); // => iwl_trans_read_prph
                    iwl_trans_release_nic_access(trans, &flags);
                }
                return val;
            }

        https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/pcie/trans.c#L1833
            static u32 iwl_trans_pcie_read_prph(struct iwl_trans *trans, u32 reg)
            {
                u32 mask = iwl_trans_pcie_prph_msk(trans); // 0x000FFFFF or 0x00FFFFFF

                iwl_trans_pcie_write32(trans, HBUS_TARG_PRPH_RADDR,
                               ((reg & mask) | (3 << 24)));
                return iwl_trans_pcie_read32(trans, HBUS_TARG_PRPH_RDAT);
            }
        """
        assert self.fd_prph_reg is not None
        os.lseek(self.fd_prph_reg, 0, os.SEEK_SET)
        os.write(self.fd_prph_reg, f"{addr:d}".encode("ascii"))
        data = os.read(self.fd_prph_reg, 128)
        matches = re.match(r"^Reg 0x([0-9a-f]+): \((0x[0-9a-f]+)\)$", data.decode("ascii"))
        if not matches:
            raise RuntimeError(f"Unexpected line from prph_reg: {data!r}")
        read_addr = int(matches.group(1), 16)
        value = int(matches.group(2), 16)
        if addr != read_addr:
            raise RuntimeError(f"Unexpected returned peripheral register {read_addr:#x} != {addr:#x}")
        return value


def get_default_debugfs_path() -> Path:
    debugfs_path: Path = next(Path("/sys/kernel/debug/iwlwifi").glob("*/"))
    print(f"Using device path: {debugfs_path}")
    return debugfs_path


def chmod_unpriv_user(args: argparse.Namespace) -> None:
    print("chmod 755 /sys/kernel/debug")
    os.chmod("/sys/kernel/debug", 0o755)

    wifi = WifiDebug(args.path)

    print(f"chmod 666 {wifi.mem_path}")
    wifi.mem_path.chmod(0o666)

    print(f"chmod 666 {wifi.prph_reg_path}")
    wifi.prph_reg_path.chmod(0o666)

    print(f"chmod 444 {wifi.fw_ver_path}")
    wifi.fw_ver_path.chmod(0o444)


def hexdump(data: bytes, start_addr: int = 0, indent: str = "", autoskip: bool = False) -> None:
    last_line_was_skipped = False
    for line_offset in range(0, len(data), 16):
        hexbytes = ""
        ascbytes = ""
        if autoskip:
            is_nul_line = all(x == 0 for x in data[line_offset:line_offset + 16])
            if last_line_was_skipped:
                if is_nul_line:
                    continue
                last_line_was_skipped = False
            elif is_nul_line:
                print(f"{indent}{start_addr + line_offset:08x}: *")
                last_line_was_skipped = True
                continue

        for offset in range(line_offset, line_offset + 16):
            if offset < len(data):
                value = data[offset]
                hexbytes += f"{value:02x}"
                ascbytes += chr(value) if 0x20 <= value < 0x7F else "."
            else:
                hexbytes += "  "
            if offset & 1:
                hexbytes += " "
        print(f"{indent}{start_addr + line_offset:08x}: {hexbytes} {ascbytes}")


def read_mem(args: argparse.Namespace) -> None:
    """Read memory using iwlmvm/mem file"""
    wifi = WifiDebug(args.path)
    wifi.open_mem()
    data = wifi.read(args.addr, args.size)
    hexdump(data, start_addr=args.addr, autoskip=args.autoskip)


def write_mem(args: argparse.Namespace) -> None:
    """Write memory using iwlmvm/mem file"""
    data = bytes.fromhex("".join(args.hexdata))
    wifi = WifiDebug(args.path)
    wifi.open_mem()
    wifi.write(args.addr, data)


def read_prph_reg(args: argparse.Namespace) -> None:
    """Read peripheral registers"""
    wifi = WifiDebug(args.path)
    wifi.open_prph_reg()
    for index in range(0, args.count):
        addr = args.addr + index * 4
        value = wifi.read_prph_reg(addr)
        if value == 0xA5A5A5A2:
            print(f"{addr:08x}: {value:#010x} => maybe DMA issue")
            time.sleep(0.5)
        else:
            print(f"{addr:08x}: {value:#010x}")


def auto_int(value: str) -> int:
    """Parse an integer or an hexadecimal integer"""
    return int(value, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interact with iwlwifi through debugfs")
    parser.add_argument(
        "-p",
        "--path",
        type=Path,
        help="path to /sys/kernel/debug/iwlwifi/0000:00:14.3 device",
    )
    subparsers = parser.add_subparsers()

    parser_chmod = subparsers.add_parser(
        "chmod-unpriv-user",
        help="enable unprivileged users to access debugfs interface",
    )
    parser_chmod.set_defaults(func=chmod_unpriv_user)

    parser_read_mem = subparsers.add_parser("read", help="read device memory")
    parser_read_mem.add_argument("addr", type=auto_int, help="address")
    parser_read_mem.add_argument("size", nargs="?", type=auto_int, default=256, help="size")
    parser_read_mem.add_argument("-a", "--autoskip", action="store_true", help="enable autoskip, replacing nul-lines with '*' (like xxd)")  # noqa
    parser_read_mem.set_defaults(func=read_mem)

    parser_write_mem = subparsers.add_parser("write", help="write device memory (when FW debug is active)")
    parser_write_mem.add_argument("addr", type=auto_int, help="address")
    parser_write_mem.add_argument("hexdata", nargs="+", type=str, help="hexadecimal content")
    parser_write_mem.set_defaults(func=write_mem)

    parser_reg = subparsers.add_parser("reg", help="read peripheral registers")
    parser_reg.add_argument("addr", type=auto_int, help="address")
    parser_reg.add_argument("count", nargs="?", type=auto_int, default=1, help="number of registers")
    parser_reg.set_defaults(func=read_prph_reg)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.error("Missing action")
    args.func(args)
