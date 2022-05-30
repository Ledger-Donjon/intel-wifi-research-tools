#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retrieve information about the running threads in UMAC CPU"""
import ctypes
import sys

from iwldebug import WifiDebug


wifi = WifiDebug()
fw_version = wifi.get_fw_ver()

if fw_version == "FW prefix: iwlwifi-9000-pu-b0-jf-b0-\nFW: release/core43::6f9f215c\nDevice: Intel(R) Wireless-AC 9560 160MHz\nBus: pci\n":  # noqa
    # Address of a list of UMAC threads
    # (Obtain this from the function which starts threads in UMAC)
    ADDR_UMAC_THREADS_COUNT = 0xc0882fb4
    ADDR_UMAC_THREADS_LIST = 0xc0882fb8
else:
    print(f"Unknown firmware version: {fw_version!r}", file=sys.stderr)
    sys.exit(1)


class ThreadInfo(ctypes.Structure):
    _fields_ = (
        ("magic", ctypes.c_uint32),  # 0x54485244, for "THRD"
        ("count_scheduled",  ctypes.c_uint32),
        ("stack_pointer",  ctypes.c_uint32),
        ("stack_bottom",  ctypes.c_uint32),
        ("stack_top",  ctypes.c_uint32),
        ("stack_size",  ctypes.c_uint32),
        ("field_0x18__for_gp_0x30",  ctypes.c_uint32),
        ("field_0x1c",  ctypes.c_uint32),
        ("prev_thread__sched",  ctypes.c_uint32),
        ("next_thread__sched",  ctypes.c_uint32),
        ("field_0x28",  ctypes.c_uint32),
        ("field_0x2c",  ctypes.c_uint32),
        ("on_exit_handler",  ctypes.c_uint32),
        ("name_ptr",  ctypes.c_uint32),
        ("priority",  ctypes.c_uint32),
        ("maybe_thread_status",  ctypes.c_uint32),
        ("maybe_thread_is_stopped",  ctypes.c_uint32),
        ("field_0x44",  ctypes.c_uint32),
        ("field_0x48",  ctypes.c_uint32),
        ("field_0x4c",  ctypes.c_uint32),
        ("start_routine",  ctypes.c_uint32),
        ("start_data",  ctypes.c_uint32),
        ("maybe_thread_subdata[0]",  ctypes.c_uint32),
        ("maybe_thread_subdata[1]",  ctypes.c_uint32),
        ("maybe_thread_subdata[2]",  ctypes.c_uint32),
        ("maybe_thread_subdata[3]",  ctypes.c_uint32),
        ("maybe_thread_subdata[4]",  ctypes.c_uint32),
        ("maybe_thread_subdata[5]",  ctypes.c_uint32),
        ("maybe_thread_subdata[6]",  ctypes.c_uint32),
        ("field_0x74",  ctypes.c_uint32),
        ("field_0x78",  ctypes.c_uint32),
        ("field_0x7c",  ctypes.c_uint32),
        ("field_0x80",  ctypes.c_uint32),
        ("field_0x84",  ctypes.c_uint32),
        ("field_0x88",  ctypes.c_uint32),
        ("field_0x8c",  ctypes.c_uint32),
        ("field_0x90",  ctypes.c_uint32),
        ("next_thread__nosched",  ctypes.c_uint32),
        ("prev_thread__nosched",  ctypes.c_uint32),
        ("field_0x9c",  ctypes.c_uint32),
        ("field_0xa0",  ctypes.c_uint32),
        ("field_0xa4",  ctypes.c_uint32),
        ("field_0xa8",  ctypes.c_uint32),
        ("field_0xac",  ctypes.c_uint32),
        ("field_0xb0",  ctypes.c_uint32),
        ("field_0xb4",  ctypes.c_uint32),
    )


assert ctypes.sizeof(ThreadInfo) == 0xb8


if __name__ == "__main__":
    wifi.open_mem()

    # The number of threads in UMAC
    umac_threads_count = wifi.read_u32(ADDR_UMAC_THREADS_COUNT)
    umac_threads_list_head = wifi.read_u32(ADDR_UMAC_THREADS_LIST)
    print(f"UMAC: {umac_threads_count} threads from {umac_threads_list_head:#010x}")
    assert umac_threads_count < 10  # It should be 3 ; limit to a known value
    current_thread_ptr = umac_threads_list_head
    for thread_idx in range(umac_threads_count):
        thread_info_raw = wifi.read(current_thread_ptr, 0xb8)
        thread_info = ThreadInfo.from_buffer_copy(thread_info_raw)

        assert thread_info.magic == 0x54485244, f"Unexpected thread magic {thread_info.magic:#x}"
        name = wifi.read(thread_info.name_ptr, 16).split(b'\0', 1)[0].decode("utf-8", "replace")
        print(f"[{thread_idx}] UMAC Thread at {current_thread_ptr:#010x}: {name!r} (priority {thread_info.priority})")

        print(f"    Stack bot/ptr/top: {thread_info.stack_bottom:#010x} {thread_info.stack_pointer:#010x} {thread_info.stack_top:#010x}, {thread_info.stack_size} bytes")  # noqa
        assert thread_info.stack_bottom < thread_info.stack_pointer < thread_info.stack_top
        assert thread_info.stack_bottom + thread_info.stack_size - 1 == thread_info.stack_top

        for key, field_type in thread_info._fields_:
            if key in {"magic", "name_ptr", "stack_pointer", "stack_bottom", "stack_top", "stack_size", "priority"}:
                continue
            value: int = getattr(thread_info, key)
            if key in {"count_scheduled"}:
                print(f"    {key} = {value}")
            elif value:  # Only display items with non-zero values
                print(f"    {key} = {value:#x}")

        print("")
        current_thread_ptr = thread_info.next_thread__nosched
