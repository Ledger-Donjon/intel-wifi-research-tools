#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retrieve information about the callout functions in LMAC and UMAC CPUs"""
import ctypes
import sys

from iwldebug import WifiDebug


wifi = WifiDebug()
fw_version = wifi.get_fw_ver()

if fw_version == "FW prefix: iwlwifi-9000-pu-b0-jf-b0-\nFW: release/core43::6f9f215c\nDevice: Intel(R) Wireless-AC 9560 160MHz\nBus: pci\n":  # noqa
    ADDR_LMAC_CALLOUT_LISTS = 0x0080a7ac
    COUNT_LMAC_CALLOUT_LISTS = 5
    ADDR_UMAC_CALLOUT_LISTS = 0xc08840c4
else:
    print(f"Unknown firmware version: {fw_version!r}", file=sys.stderr)
    sys.exit(1)


class CalloutList(ctypes.Structure):
    _fields_ = (
        ("head", ctypes.c_uint32),
        ("tail",  ctypes.c_uint32),
        ("hw_interrupt_cfg",  ctypes.c_uint32),
        ("hw_interrupt_timeval",  ctypes.c_uint32),
        ("hw_current_time",  ctypes.c_uint32),
        ("hwbits_to_set",  ctypes.c_uint32),
        ("hwbits_to_clear",  ctypes.c_uint32),
        ("first_item_with_flag_2",  ctypes.c_uint32),
        ("first_item_with_flag_8",  ctypes.c_uint32),
    )


assert ctypes.sizeof(CalloutList) == 0x24


class CalloutItem(ctypes.Structure):
    _fields_ = (
        ("next", ctypes.c_uint32),
        ("prev",  ctypes.c_uint32),
        ("time_to_trigger",  ctypes.c_uint32),
        ("callback",  ctypes.c_uint32),
        ("flags",  ctypes.c_uint32),
        ("unknown",  ctypes.c_uint32),
        ("list",  ctypes.c_uint32),
        ("umac_unique_id",  ctypes.c_uint32),  # Only used in UMAC
    )


assert ctypes.sizeof(CalloutItem) == 0x20


def difftime(time1: int, time2: int) -> int:
    """Return a time difference, between -0x80000000 and 0x80000000"""
    delta = time1 - time2
    if delta >= 0x80000000:
        return delta - 0x100000000
    if delta < -0x80000000:
        return delta + 0x100000000
    return delta


def show_callout_list(name: str, list_addr: int, is_umac: bool) -> None:
    print(f"{name} from {list_addr:#010x}")
    callout_list = CalloutList.from_buffer_copy(wifi.read(list_addr, 0x24))
    int_cfg = wifi.read_u32(callout_list.hw_interrupt_cfg)
    int_timeval = wifi.read_u32(callout_list.hw_interrupt_timeval)
    current_time = wifi.read_u32(callout_list.hw_current_time)
    print(
        "  HW registers: "
        f"{callout_list.hw_interrupt_cfg:#010x} (={int_cfg:#x}), "
        f"{callout_list.hw_interrupt_timeval:#010x} (={int_timeval}), "
        f"{callout_list.hw_current_time:#010x} (={current_time})")
    print(f"  HW bits: set {callout_list.hwbits_to_set:#x}, clear {callout_list.hwbits_to_clear:#x}")
    if int_timeval != 0:
        print(f"  ... will trigger in {difftime(int_timeval, current_time)} microsecs")
    if callout_list.head != list_addr or callout_list.tail != list_addr:
        print(f"  list: head {callout_list.head:#010x}, tail {callout_list.tail:#010x}")
    if callout_list.first_item_with_flag_2:
        print(f"  first_item_with_flag_2 = {callout_list.first_item_with_flag_2:#010x}")
    if callout_list.first_item_with_flag_8:
        print(f"  first_item_with_flag_8 = {callout_list.first_item_with_flag_8:#010x}")

    if 0:  # Dump the structure
        for key, field_type in callout_list._fields_:
            value: int = getattr(callout_list, key)
            print(f"    {key} = {value:#x}")

    # Dump as most items as possible, considering they are changing quickly
    wanted_items = [
        callout_list.head,
        callout_list.tail,
        callout_list.first_item_with_flag_2,
        callout_list.first_item_with_flag_8,
    ]
    # 0xdead0002 is inserted when a callout expires
    dumped_items = set((0, list_addr, 0xdead0002))

    while wanted_items:
        item_addr = wanted_items.pop(0)
        if item_addr in dumped_items:
            continue
        callout_item = CalloutItem.from_buffer_copy(wifi.read(item_addr, 0x20))
        print(f"  - item@{item_addr:#010x}: prev {callout_item.prev:#010x}, next {callout_item.next:#010x}")
        print(f"    time {callout_item.time_to_trigger} "
              f"(in {difftime(callout_item.time_to_trigger, current_time)} microsecs)")
        print(f"    callback {callout_item.callback:#010x}")
        print(f"    flags {callout_item.flags:#010x}, unknown {callout_item.unknown:#x}" +
              (f", id {callout_item.umac_unique_id:#x}" if is_umac else ""))
        if callout_item.list != list_addr:
            print(f"    WARNING: list={callout_item.list:#010x} unexpected")

        # Insert prev too, so that it is dumped after next if it was not dumped
        wanted_items.insert(0, callout_item.prev)
        wanted_items.insert(0, callout_item.next)
        dumped_items.add(item_addr)


if __name__ == "__main__":
    wifi.open_mem()

    for idx in range(COUNT_LMAC_CALLOUT_LISTS):
        show_callout_list(f"LMAC Callout list {idx}", ADDR_LMAC_CALLOUT_LISTS + 0x24 * idx, False)
        print("")
    show_callout_list("UMAC Callout list", ADDR_UMAC_CALLOUT_LISTS, True)
