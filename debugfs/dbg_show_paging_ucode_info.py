#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retrieve information about the Paging microcode of the UMAC CPU"""
import struct
import sys

from iwldebug import WifiDebug


wifi = WifiDebug()
fw_version = wifi.get_fw_ver()

if fw_version == "FW prefix: iwlwifi-9000-pu-b0-jf-b0-\nFW: release/core43::6f9f215c\nDevice: Intel(R) Wireless-AC 9560 160MHz\nBus: pci\n":  # noqa
    # Address where the LEGACY/FW_PAGING_BLOCK_CMD = 0x4F command is stored
    # (Obtain this from the command handler in UMAC)
    ADDR_PAGING_CMD_FROM_HOST = 0xc0885774

    # Mapping of page numbers, intialized to 0xff in the FW_PAGING_BLOCK_CMD handler
    ADDR_PAGING_VIRT2PHYS_MAP = 0x804508b8

    # Information from the firmware file, paging area
    ADDR_PAGING_VIRT_BEGIN = 0x01000000
    # ADDR_PAGING_VIRT_END = 0x0103b000  # This was modified in the patched firmware

    # Physical memory area
    ADDR_PAGING_PHYS_BEGIN = 0x80422000
    ADDR_PAGING_PHYS_END = 0x80448000

    # Checksums
    ADDR_PAGING_CKSUMS = 0x8048f400

    # Hardware registers used to store information about the page mapping configuration
    # (list of virtual pages)
    ADDR_HW_PAGEMAP_INFO = 0xc0a05200
else:
    print(f"Unknown firmware version: {fw_version!r}", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    wifi.open_mem()

    # Read struct iwl_fw_paging_cmd header
    paging_cmd_header = wifi.read(ADDR_PAGING_CMD_FROM_HOST, 0xc)
    paging_cmd_flags, paging_cmd_block_size, paging_cmd_block_num = struct.unpack("<3I", paging_cmd_header)
    blk_bytes = 1 << paging_cmd_block_size
    print(f"FW_PAGING_BLOCK_CMD at {ADDR_PAGING_CMD_FROM_HOST:#010x}:")
    # #define PAGING_CMD_IS_SECURED BIT(9)
    # #define PAGING_CMD_IS_ENABLED BIT(8)
    print(f"* flags = {paging_cmd_flags:#x}: secured={paging_cmd_flags & (1 << 9):#x}, enabled={paging_cmd_flags & (1 << 8):#x}, num_pages_in_last_block={paging_cmd_flags & 0xff}")  # noqa
    print(f"* block_size = {paging_cmd_block_size} ({blk_bytes:#x} = {blk_bytes} bytes/block, {blk_bytes >> 12} pages/block)")  # noqa
    print(f"* block_num = {paging_cmd_block_num}")
    paging_size = (paging_cmd_block_num - 1) * blk_bytes + ((paging_cmd_flags & 0xff) << 12)
    print(f"=> total paging size: {paging_size:#x} = {paging_size // 1024} KB = {paging_size >> 12} pages")

    assert paging_cmd_block_size >= 12, "block size must be larger than 4 KB page size"

    # Read struct iwl_fw_paging_cmd data
    paging_cmd_device_phy_addr_raw = wifi.read(ADDR_PAGING_CMD_FROM_HOST + 0xc, 4 * (paging_cmd_block_num + 1))
    paging_cmd_device_phy_addr = struct.unpack(f"<{paging_cmd_block_num + 1}I", paging_cmd_device_phy_addr_raw)
    print("Block addresses:")
    for idx, host_pfn in enumerate(paging_cmd_device_phy_addr):
        host_addr = host_pfn << 12
        if idx == 0:
            print(f"  Host phys {host_addr:#010x} = Header with signature")
        else:
            print(f"  Host phys {host_addr:#010x} = Paging ucode {ADDR_PAGING_VIRT_BEGIN + (idx - 1) * blk_bytes:#010x}")  # noqa
    print("")

    total_avail_phys_pages = (ADDR_PAGING_PHYS_END - ADDR_PAGING_PHYS_BEGIN) >> 12

    # Read virt page info from hardware registers (two identical 128 bytes)
    hw_pagemap_info_raw = wifi.read(ADDR_HW_PAGEMAP_INFO, 0x100)
    assert hw_pagemap_info_raw[:0x80] == hw_pagemap_info_raw[0x80:0x100]
    hw_pagemap_info = struct.unpack(f"<{len(hw_pagemap_info_raw) // 4}H", hw_pagemap_info_raw[:0x80])
    print("Hardware virtual page info:")
    is_last_03ff = False
    for idx, value in enumerate(hw_pagemap_info):
        if value == 0x03ff:
            if not is_last_03ff:
                print(f"  [{idx:3}] ({value:#06x}) -")
            is_last_03ff = True
            continue
        # assert is_last_03ff is False
        virt_pfn = value & 0x03ff
        virt_addr = ADDR_PAGING_VIRT_BEGIN + (virt_pfn << 12)
        print(f"  [{idx:3}] ({value:#06x}) virt {virt_addr:#010x}")
        if idx == total_avail_phys_pages - 1:
            print(f"  -- {total_avail_phys_pages} physical pages")
    print("")

    # Read checksums
    try:
        page_checksums_raw = wifi.read(ADDR_PAGING_CKSUMS, (paging_size >> 12) * 4)
    except OSError:
        # This happens with stock firmware
        page_checksums = None
    else:
        page_checksums = struct.unpack(f"<{paging_size >> 12}I", page_checksums_raw)

    # Read WiFi virtual-to-physical configuration
    assert paging_cmd_block_num * blk_bytes <= 256 * 4096
    virt2phys_map = wifi.read(ADDR_PAGING_VIRT2PHYS_MAP, paging_cmd_block_num << (paging_cmd_block_size - 12))
    print(f"Raw virt-to-phys paging map at {ADDR_PAGING_VIRT2PHYS_MAP:#010x}:")
    for idx in range(0, len(virt2phys_map), 16):
        print("  " + " ".join(f"{x:02x}" for x in virt2phys_map[idx:idx + 16]))

    used_phys_pfnindexes = set()
    print("Decoded:")
    for idx, value in enumerate(virt2phys_map):
        virt_addr = ADDR_PAGING_VIRT_BEGIN + (idx << 12)
        host_pfn_of_block = paging_cmd_device_phy_addr[1 + (idx >> (paging_cmd_block_size - 12))]
        host_addr = (host_pfn_of_block << 12) + ((idx << 12) & (blk_bytes - 1))

        if page_checksums is not None and idx < len(page_checksums):
            cksum_desc = f" cksum={page_checksums[idx]:#010x}"
        else:
            cksum_desc = ""

        if value == 0xff:
            print(f"  ({value:02x}) {virt_addr:#010x} -> -                (host {host_addr:#010x}){cksum_desc}")
        elif value == 0xfe:
            print(f"  ({value:02x}) {virt_addr:#010x} -> out of bounds{cksum_desc}")
        else:
            phys_addr = ADDR_PAGING_PHYS_BEGIN + (value << 12)
            assert phys_addr < ADDR_PAGING_PHYS_END
            print(f"  ({value:02x}) {virt_addr:#010x} -> phys {phys_addr:#010x}  (host {host_addr:#010x}){cksum_desc}")
            assert value not in used_phys_pfnindexes, "Duplicate use of the same phys page!"
            used_phys_pfnindexes.add(value)

    used_phys_pages = len(used_phys_pfnindexes)
    free_phys_pages = total_avail_phys_pages - used_phys_pages
    print(f"=> physical pages: {used_phys_pages} used + {free_phys_pages} free = {total_avail_phys_pages}")
