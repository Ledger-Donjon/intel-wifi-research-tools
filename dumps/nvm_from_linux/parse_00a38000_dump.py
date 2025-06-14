#!/usr/bin/env python3
"""
Usage:
    flake8 --max-line-length=120 parse_00a38000_dump.py && mypy --strict parse_00a38000_dump.py && \
    ./parse_00a38000_dump.py && ./parse_00a38000_dump.py > OUT_dump_hw_00a38000_wirelessAC_9560.parsed.txt
"""
import enum
import hashlib
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple


BASE_DIR = Path(__file__).parent

DO_DUMP_HEX = False


@enum.unique
class NvmSectionType(enum.IntEnum):
    """enum iwl_nvm_section_type from Linux driver and custom additions

    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlwifi/fw/api/nvm-reg.h?h=v5.12#n64
    """

    SW = 1
    REGULATORY = 3
    CALIBRATION = 4
    PRODUCTION = 5
    BOOTROM_CONFIG = 6
    BOOTROM_RSAKEY = 7  # Key which is loaded when loadflags&0x80 is clear
    REGULATORY_SDP = 8
    HW = 10
    MAC_OVERRIDE = 11
    PHY_SKU = 12

    @property
    def debugfs_filename(self) -> Optional[str]:
        """File /sys/kernel/debug/iwlwifi/*/iwlmvm/nvm_...

        https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlwifi/mvm/nvm.c?h=v5.12#n340
        """
        if self == self.SW:
            return "nvm_sw"
        if self == self.REGULATORY or self == self.REGULATORY_SDP:
            return "nvm_reg"
        if self == self.CALIBRATION:
            return "nvm_calib"
        if self == self.PRODUCTION:
            return "nvm_prod"
        if self == self.HW:
            return "nvm_hw"
        if self == self.PHY_SKU:
            return "nvm_phy_sku"
        return None


# Load NVM dumps
all_nvm_dumps: Dict[str, Tuple[str, bytes]] = {}
for nvm_dump_path in (BASE_DIR / "wirelessAC_9560_nvm_dump/").glob("*.bin"):
    with nvm_dump_path.open("rb") as nvmfd:
        nvm_data = nvmfd.read()
    nvm_data_hash = hashlib.sha256(nvm_data).hexdigest()
    assert (
        nvm_data_hash not in all_nvm_dumps
    ), f"Duplicate dump with SHA256 {nvm_data_hash}"
    all_nvm_dumps[nvm_data_hash] = (nvm_dump_path.name, nvm_data)


dump_hw_00a38000: List[int] = []
with (BASE_DIR / "dump_hw_00a38000_wirelessAC_9560.txt").open("r") as fd:
    for line in fd:
        if not line.startswith("HWReg@a38000"):
            continue
        matches = re.match(
            r"^HWReg@a38000\[0x([0-9a-f]{4})\]: ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})$",  # noqa
            line,
        )
        assert matches, f"Unexpected line {line!r}"
        values = [int(x, 16) for x in matches.groups()]
        assert values[0] == len(dump_hw_00a38000) * 4
        dump_hw_00a38000 += values[1:]


assert len(dump_hw_00a38000) == 0x8000 // 4

current_index = 0
index_start_current = 0
is_last_empty = False
while current_index < len(dump_hw_00a38000):
    if dump_hw_00a38000[current_index] == 0:
        # Skip empty entries
        if not is_last_empty:
            if DO_DUMP_HEX:
                for index in range(index_start_current, current_index, 8):
                    cur_line = " ".join(
                        f"{dump_hw_00a38000[i]:#010x}" for i in range(index, min(current_index, index + 8)))
                    print(f"{0x00a38000 + index * 4:08x}: {cur_line}")
            print(f"{current_index * 4:04x}: ---------------------------------")
        is_last_empty = True
        current_index += 1
        continue

    if is_last_empty:
        print("")
        print(f"*********************** NEW NVM TARGET @{current_index * 4:04x} ***********************")
        print("")
        index_start_current = current_index
    is_last_empty = False

    header = dump_hw_00a38000[current_index]
    header_type = header >> 28
    header_unknown = (header & 0x00FFC000) >> 14
    header_u32count = header & 0x7FF

    if DO_DUMP_HEX:
        # Only dump hexadecimal content
        current_index += 1 + header_u32count
        continue

    type_name = f"{header_type:2}" + (
        f".{header_unknown:2}" if header_unknown else "   "
    )
    print(
        f"{current_index * 4:04x}: type={type_name} count={header_u32count:3} ({header:#010x})"
    )
    assert (header & 0x0F003800) == 0, f"Unexpected header {header:#010x}"
    assert header == (header_type << 28) + (header_unknown << 14) + header_u32count

    # Compute the SHA256 of the content, to match with NVM
    content_digest = hashlib.sha256()
    for i in range(header_u32count):
        content_digest.update(
            dump_hw_00a38000[current_index + 1 + i].to_bytes(4, "little")
        )
    content_hash = content_digest.hexdigest()
    try:
        nvm_file_name, nvm_data = all_nvm_dumps[content_hash]
    except KeyError:
        has_nvm_dump = False
    else:
        has_nvm_dump = True
        assert len(nvm_data) == 4 * header_u32count, "Size mismatch!"
        print(f"  => Match NVM dump file {nvm_file_name!r}")

    if header_unknown == 0:
        try:
            sec_type = NvmSectionType(header_type)
        except ValueError:
            pass
        else:
            print(f"  => NVM section type {sec_type.name}")
            debugfs_filename = sec_type.debugfs_filename
            if debugfs_filename:
                if has_nvm_dump:
                    print(
                        f"  => hexdump -C /sys/kernel/debug/iwlwifi/*/iwlmvm/{debugfs_filename}"
                    )
                else:
                    print(
                        f"  => but not the same as /sys/kernel/debug/iwlwifi/*/iwlmvm/{debugfs_filename}"
                    )

    if (
        header_type == NvmSectionType.BOOTROM_CONFIG
        and dump_hw_00a38000[current_index + 1] == 0xB0010ADE
    ):
        print("  => Boot configuration read by the BootROM")
        print(f"    [+ 0] {dump_hw_00a38000[current_index + 1]:#010x} = magic")
        print(
            f"    [+ 1] {dump_hw_00a38000[current_index + 2]:#010x} = unknown, must be lower than 0x100"
        )
        print(
            f"    [+ 2] {dump_hw_00a38000[current_index + 3]:#010x} = boot load flags"
        )
        print(
            f"    [+ 3] {dump_hw_00a38000[current_index + 4]:#010x} = [directload] offset for code"
        )
        print(
            f"    [+ 4] {dump_hw_00a38000[current_index + 5]:#010x} = [directload] u32count for code"
        )
        print(
            f"    [+ 5] {dump_hw_00a38000[current_index + 6]:#010x} = [directload] offset for data"
        )
        print(
            f"    [+ 6] {dump_hw_00a38000[current_index + 7]:#010x} = [directload] u32count for data"
        )
        print(
            f"    [+ 7] {dump_hw_00a38000[current_index + 8]:#010x} = [directload] address of loaded code"
        )
        print(
            f"    [+ 8] {dump_hw_00a38000[current_index + 9]:#010x} = [directload] address of loaded data"
        )
        print(
            f"    [+ 9] {dump_hw_00a38000[current_index +10]:#010x} = address of FW header for CPU 0"
        )
        print(
            f"    [+10] {dump_hw_00a38000[current_index +11]:#010x} = address of FW header for CPU 1"
        )

    if header_type == NvmSectionType.SW and header_u32count >= 2:
        print("  => Try to extract info like iwl-nvm-parse.c")
        print(f"    [+ 0] {dump_hw_00a38000[current_index + 1]:#x} = version")
        print(
            f"    [+ 1.hiu16] {dump_hw_00a38000[current_index + 2] >> 16:#x} = n_hw_addr (number of MAC addresses)"
        )

    if header_type == NvmSectionType.PHY_SKU and header_u32count >= 2:
        print("  => Try to extract info like iwl-nvm-parse.c")
        # iwl-drv.h:
        #     #define EXT_NVM_RF_CFG_FLAVOR_MSK(x)   ((x) & 0xF)
        #     #define EXT_NVM_RF_CFG_DASH_MSK(x)   (((x) >> 4) & 0xF)
        #     #define EXT_NVM_RF_CFG_STEP_MSK(x)   (((x) >> 8) & 0xF)
        #     #define EXT_NVM_RF_CFG_TYPE_MSK(x)   (((x) >> 12) & 0xFFF)
        #     #define EXT_NVM_RF_CFG_TX_ANT_MSK(x) (((x) >> 24) & 0xF)
        #     #define EXT_NVM_RF_CFG_RX_ANT_MSK(x) (((x) >> 28) & 0xF)
        radio_cfg = dump_hw_00a38000[current_index + 1]
        print(f"    [+ 0] {radio_cfg:#010x} = radio CFG")
        print(f"                 {radio_cfg & 0xf:#x} = radio_cfg_pnum")
        print(f"                 {(radio_cfg >> 4) & 0xf:#x} = radio_cfg_dash")
        print(f"                 {(radio_cfg >> 8) & 0xf:#x} = radio_cfg_step")
        print(f"               {(radio_cfg >> 12) & 0xfff:#5x} = radio_cfg_type")
        print(f"                 {(radio_cfg >> 24) & 0xf:#x} = valid_tx_ant")
        print(f"                 {(radio_cfg >> 28) & 0xf:#x} = valid_rx_ant")
        print(f"    [+ 1] {dump_hw_00a38000[current_index + 2]:#x} = SKU")

    if header_type == NvmSectionType.HW:
        # Decode HW register assignations
        for hw_offset in range(0, header_u32count, 2):
            hwreg_addr = dump_hw_00a38000[current_index + 1 + hw_offset]
            hwreg_value = dump_hw_00a38000[current_index + 2 + hw_offset]
            if hwreg_addr == 0x00A03080:
                # Wireless Flow Management Protocol (WFMP) MAC address
                # With 4c:1d:96:b8:22:ed => WFMP_MAC_ADDR_0 = 0x4c1d96b8
                print(
                    f"    [+{hw_offset:3}] WFMP_MAC_ADDR_0@{hwreg_addr:#x} = {hwreg_value:#x}"
                )
            elif hwreg_addr == 0x00A03084:
                # With 4c:1d:96:b8:22:ed => WFMP_MAC_ADDR_1 = 0x22ed
                print(
                    f"    [+{hw_offset:3}] WFMP_MAC_ADDR_1@{hwreg_addr:#x} = {hwreg_value:#x}"
                )
            elif hwreg_addr == 0x00A03088:
                print(
                    f"    [+{hw_offset:3}] fwload_flags@{hwreg_addr:#x} = {hwreg_value:#x}"
                )

    # Hexdump
    for line_idx in range(0, header_u32count, 4):
        hex_line = ""
        asc_line = ""
        for col_idx in range(4):
            if line_idx + col_idx < header_u32count:
                val = dump_hw_00a38000[current_index + 1 + line_idx + col_idx]
                hex_line += f" {val:08x}"
                asc_line += "".join(
                    chr(c) if 32 <= c < 127 else "." for c in val.to_bytes(4, "little")
                )
            else:
                hex_line += "         "
        print(f"  [+{line_idx:03x}]{hex_line}  {asc_line}")

    print("")
    current_index += 1 + header_u32count
