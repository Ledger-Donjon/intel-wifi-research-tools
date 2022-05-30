#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retrieve information about the DMA queues shared with the host, dynamically"""
import ctypes
import sys

from iwldebug import WifiDebug


wifi = WifiDebug()
fw_version = wifi.get_fw_ver()

if "\nDevice: Intel(R) Wireless-AC 9560 160MHz\n" in fw_version:  # noqa
    # Hardware device with queues, configured in cmd 0x05 (DATA_PATH) / 0x0d (RFH_QUEUE_CONFIG)
    ADDR_HW_RFH_RXF_RXQ_ACTIVE = 0xC0A0980C
    ADDR_HW_RFH_RXF_DMA_CFG = 0xC0A09820
    ADDR_HW_RFH_GEN_CFG = 0xC0A09800
    ADDR_HW_RFH_GEN_STATUS = 0xC0A09808

    ADDR_HW_FH_MEM_LOWER_BOUND = 0xC0001000
    ADDR_HW_FH_TSSR_TX_STATUS_REG = ADDR_HW_FH_MEM_LOWER_BOUND + 0xEA0 + 0x010
    ADDR_HW_FH_TSSR_TX_ERROR_REG = ADDR_HW_FH_MEM_LOWER_BOUND + 0xEA0 + 0x018

    ADDR_HW_RFH_Q_FRBDCB_BA = 0xC0A08000  # DMA address of RBD free table (BA = "Base Address"?)
    ADDR_HW_RFH_Q_FRBDCB_WIDX = 0xC0A08080  # Initial index of the free table
    ADDR_HW_RFH_Q_FRBDCB_RIDX = 0xC0A080C0
    ADDR_HW_RFH_Q_URBDCB_BA = 0xC0A08100  # DMA address of RBD used table
    ADDR_HW_RFH_Q_URBDCB_WIDX = 0xC0A08180
    ADDR_HW_RFH_Q_URBDCB_VAID = 0xC0A081C0
    ADDR_HW_RFH_Q_URBD_STTS_WPTR = 0xC0A08200  # DMA address of urbd_stts_wrptr (where in DRAM to update its Rx status)

else:
    print(f"Unknown firmware version: {fw_version!r}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    wifi.open_mem()

    print(f"RFH_RXF_RXQ_ACTIVE = {wifi.read_u32(ADDR_HW_RFH_RXF_RXQ_ACTIVE):#010x}")
    print(f"RFH_RXF_DMA_CFG = {wifi.read_u32(ADDR_HW_RFH_RXF_DMA_CFG):#010x}")
    print(f"RFH_GEN_CFG = {wifi.read_u32(ADDR_HW_RFH_GEN_CFG):#010x}")
    print(f"RFH_GEN_STATUS = {wifi.read_u32(ADDR_HW_RFH_GEN_STATUS):#010x}")
    print(f"FH_TSSR_TX_STATUS_REG = {wifi.read_u32(ADDR_HW_FH_TSSR_TX_STATUS_REG):#010x}")
    print(f"FH_TSSR_TX_ERROR_REG = {wifi.read_u32(ADDR_HW_FH_TSSR_TX_ERROR_REG):#010x}")

    for q_num in range(16):
        frbdcb_ba = wifi.read_u64(ADDR_HW_RFH_Q_FRBDCB_BA + 8 * q_num)
        if frbdcb_ba >> 48:
            print(f"Queue {q_num:2}: RFH_Q_FRBDCB_BA too big ({frbdcb_ba:#x})")
            continue
        print(f"Queue {q_num:2}:")
        addr = ADDR_HW_RFH_Q_FRBDCB_BA + 8 * q_num
        print(f"  - @{addr:#010x} RFH_Q_FRBDCB_BA   = {wifi.read_u64(addr):#x}")
        addr = ADDR_HW_RFH_Q_FRBDCB_WIDX + 4 * q_num
        print(f"  - @{addr:#010x} RFH_Q_FRBDCB_WIDX = {wifi.read_u32(addr):#x}")
        addr = ADDR_HW_RFH_Q_FRBDCB_RIDX + 4 * q_num
        print(f"  - @{addr:#010x} RFH_Q_FRBDCB_RIDX = {wifi.read_u32(addr):#x}")
        addr = ADDR_HW_RFH_Q_URBDCB_BA + 8 * q_num
        print(f"  - @{addr:#010x} RFH_Q_URBDCB_BA   = {wifi.read_u64(addr):#x}")
        addr = ADDR_HW_RFH_Q_URBDCB_WIDX + 8 * q_num
        print(f"  - @{addr:#010x} RFH_Q_URBDCB_WIDX = {wifi.read_u32(addr):#x}")
        addr = ADDR_HW_RFH_Q_URBDCB_VAID + 8 * q_num
        print(f"  - @{addr:#010x} RFH_Q_URBDCB_VAID = {wifi.read_u32(addr):#x}")
        addr = ADDR_HW_RFH_Q_URBD_STTS_WPTR + 8 * q_num
        print(f"  - @{addr:#010x} RFH_Q_URBD_STTS_WPTR = {wifi.read_u64(addr):#x}")
