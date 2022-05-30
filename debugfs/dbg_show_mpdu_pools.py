#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retrieve information about the received Wi-Fi MPDU"""
import ctypes
import struct
import sys

from iwldebug import WifiDebug, hexdump


wifi = WifiDebug()
fw_version = wifi.get_fw_ver()

if fw_version == "FW prefix: iwlwifi-9000-pu-b0-jf-b0-\nFW: release/core43::6f9f215c\nDevice: Intel(R) Wireless-AC 9560 160MHz\nBus: pci\n":  # noqa
    # Address of 3 MPDU pools, which references (in name) the strings "MPDU_FRWK_0", "MPDU_FRWK_1"...
    ADDR_UMAC_MPDU_POOLS = 0xc0883d54
    COUNT_UMAC_MPDU_POOLS = 3
else:
    print(f"Unknown firmware version: {fw_version!r}", file=sys.stderr)
    sys.exit(1)


class ThreadXBlockPool(ctypes.Structure):
    """TX_BLOCK_POOL structure

    https://github.com/azure-rtos/threadx/blob/v6.1_rel/common/inc/tx_api.h#L494
    """
    _fields_ = (
        ("magic", ctypes.c_uint32),
        ("name", ctypes.c_uint32),
        ("available", ctypes.c_uint32),
        ("total",  ctypes.c_uint32),
        ("available_bitmask",  ctypes.c_uint32),
        ("pool_start",  ctypes.c_uint32),
        ("pool_size",  ctypes.c_uint32),
        ("pool_block_size",  ctypes.c_uint32),
        ("suspension_list",  ctypes.c_uint32),
        ("suspended_count",  ctypes.c_uint32),
        ("block_pool_created_next",  ctypes.c_uint32),
        ("block_pool_created_previous",  ctypes.c_uint32),
        ("id_for_tracing",  ctypes.c_uint32),
    )


assert ctypes.sizeof(ThreadXBlockPool) == 0x34


class UmacMpduFrwkPool(ctypes.Structure):
    _fields_ = (
        ("block_pool", ThreadXBlockPool),
        ("block_size", ctypes.c_uint32),
        ("max_itemcount", ctypes.c_uint32),
        ("pool_size", ctypes.c_uint32),
        ("pool_start", ctypes.c_uint32),
        ("name", ctypes.c_uint32),
        ("num_allocated_blocks", ctypes.c_uint32),
        ("first_allocated_block", ctypes.c_uint32),
        ("last_allocated_block", ctypes.c_uint32),
        ("stat_max_number_allocated_blocks", ctypes.c_uint32),
        ("other_num_allocated_blocks", ctypes.c_uint32),
    )


assert ctypes.sizeof(UmacMpduFrwkPool) == 0x5c


if __name__ == "__main__":
    wifi.open_mem()

    for pool_idx in range(COUNT_UMAC_MPDU_POOLS):
        pool_addr = ADDR_UMAC_MPDU_POOLS + 0x5c * pool_idx
        pool = UmacMpduFrwkPool.from_buffer_copy(wifi.read(pool_addr, 0x5c))

        if 0:  # Dump the structure
            for key, field_type in pool.block_pool._fields_:
                value: int = getattr(pool.block_pool, key)
                print(f"    block_pool.{key} = {value:#x}")
            for key, field_type in pool._fields_:
                if key == "block_pool":
                    continue
                value = getattr(pool, key)
                print(f"    {key} = {value:#x}")

        assert pool.block_pool.magic == 0x424c4f43, f"Unexpected magic {pool.block_pool.magic:#x}"  # BLOC
        assert pool.block_pool.name == pool.name
        assert pool.block_pool.available <= pool.block_pool.total
        assert pool.block_pool.total == pool.max_itemcount
        assert pool.block_pool.pool_start == pool.pool_start
        assert pool.block_pool.pool_size == pool.pool_size
        assert pool.block_pool.pool_block_size == pool.block_size

        pool_name = wifi.read(pool.name, 16).split(b"\0", 1)[0].decode()

        print(f"{pool_name!r} (id {pool.block_pool.id_for_tracing} @{pool_addr:#x}):")
        print(f"  data: {pool.block_pool.pool_start:#010x}..{pool.block_pool.pool_start + pool.pool_size:#010x}")
        print(f"  size {pool.pool_size:#x} = {pool.pool_size} = {pool.max_itemcount} * ({pool.block_size} + 4) bytes")
        print(f"  avail {pool.block_pool.available} (bitmask {pool.block_pool.available_bitmask:#x})")
        print(f"  num_allocated_blocks = {pool.num_allocated_blocks}")
        if pool.first_allocated_block:
            print(f"  first_allocated_block = {pool.first_allocated_block:#010x}")
        if pool.last_allocated_block:
            print(f"  last_allocated_block  = {pool.last_allocated_block:#010x}")
        print(f"  stat_max_number_allocated_blocks = {pool.stat_max_number_allocated_blocks}")
        print(f"  other_num_allocated_blocks = {pool.other_num_allocated_blocks}")
        assert pool.max_itemcount * (pool.block_size + 4) == pool.pool_size

        pool_blocks = wifi.read(pool.pool_start, pool.pool_size)
        for block_idx in range(pool.max_itemcount):
            block_offset = block_idx * pool.block_size
            block_addr = pool.pool_start + block_offset
            block_data = pool_blocks[block_offset:block_offset + pool.block_size]
            if block_data == b"\0" * pool.block_size:
                continue
            if pool.block_pool.available_bitmask & (1 << block_idx):
                block_desc = "free"
            else:
                block_desc = "allocated"
            stripped_block = block_data.rstrip(b"\0")
            print(f"  - Block {block_idx:2} @{block_addr:#010x}: {block_desc} ({len(stripped_block)} bytes)")

            # hexdump(block_data, indent="      ")

            blk_prev, blk_next, blk_pool = struct.unpack("<3I", block_data[:0xc])
            if blk_prev:
                print(f"    [0000] prev = {blk_prev:#010x}")
            if blk_next:
                print(f"    [0004] next = {blk_next:#010x}")
            if blk_pool:
                print(f"    [0008] pool = {blk_pool:#010x}")
                assert blk_pool == pool_addr

            unk_fields = struct.unpack("<10I", block_data[0xc:0x34])
            data_header = block_data[0x34:0x6c]
            data_payload = block_data[0x6c:]

            for field_idx, field_val in enumerate(unk_fields):
                if field_idx == 5:
                    print(f"    [{0xc + field_idx * 4:04x}] destructor_param = {field_val:#010x}")
                elif field_idx == 6:
                    print(f"    [{0xc + field_idx * 4:04x}] destructor_fct = {field_val:#010x}")
                elif field_idx == 7:
                    print(f"    [{0xc + field_idx * 4:04x}] timestamp = {field_val}")
                elif field_val:
                    print(f"    [{0xc + field_idx * 4:04x}] unk_{field_idx} = {field_val:#x}")
            print("    [0034] Header (maybe 2 uint + struct rx_mpdu_desc):")
            hexdump(data_header, indent="      ")
            print("    [006c] Payload (struct ieee80211_hdr):")
            hexdump(data_payload.rstrip(b"\0"), indent="      ")

        print("")
