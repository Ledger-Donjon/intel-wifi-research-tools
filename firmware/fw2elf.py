#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Craft an ELF file from an Intel Wi-Fi microcode file

Reformat with: black --line-length=120
"""
import argparse
from pathlib import Path
import struct
from typing import Dict, Optional, Tuple

from parse_intel_wifi_fw import IntelWifiFirmware, UcodeTlvType


class DataSegments:
    """Collection of data segments with addresses"""

    def __init__(self) -> None:
        # Initialized segments are represented as start => (name, end, data)
        # Uninitialized segments are represented as start => (name, end, None)
        self.segments: Dict[int, Tuple[str, int, Optional[bytes]]] = {}

    def add_segment(self, addr: int, data: bytes, name: Optional[str] = None) -> None:
        # Ensure the segment does not conflict with existing ones
        addr_end = addr + len(data)
        for seg_addr, seg_name_end_data in self.segments.items():
            seg_addr_end = seg_name_end_data[1]
            if seg_addr < addr_end and addr < seg_addr_end:
                raise ValueError(f"Refusing to add segment {addr:#x}..{addr_end:#x} because it overlaps with {seg_addr:#x}..{seg_addr_end:#x}")
        if not name:
            name = f"seg_{addr:08x}"
        self.segments[addr] = (name, addr_end, data)

    def add_uninitialized_segment(self, addr: int, size: int, name: Optional[str] = None) -> None:
        # Ensure the segment does not conflict with existing ones
        addr_end = addr + size
        for seg_addr, seg_name_end_data in self.segments.items():
            seg_addr_end = seg_name_end_data[1]
            if seg_addr < addr_end and addr < seg_addr_end:
                raise ValueError(f"Refusing to add segment {addr:#x}..{addr_end:#x} because it overlaps with {seg_addr:#x}..{seg_addr_end:#x}")
        if not name:
            name = f"uninitseg_{addr:08x}"
        self.segments[addr] = (name, addr_end, None)

    def to_elf(self) -> bytes:
        # Craft ELF program and section headers
        file_data = b""
        sections = self.segments
        num_ph_entries = len(sections)
        num_sh_entries = len(sections) + 4  # NULL, sections, .symtab, .strtab and .shstrtab
        offset_data = 0x34 + 0x20 * num_ph_entries  # ELF section + program headers
        skipped_sections = 0

        # Align the offset of file data
        offset_data = ((offset_data + 511) // 512) * 512
        base_offset_data = offset_data
        prog_header = []
        sect_header = []
        # SHT_NULL entry
        sect_header.append(b"\0" * 0x28)
        shstrtab = b"\0\0\0\0"

        # Symbol table
        symtab = [b"\0" * 0x10]
        symstrtab = b"\0\0\0\0"

        for seg_addr, seg_name_end_data in sorted(self.segments.items()):
            seg_name, seg_addr_end, seg_data = seg_name_end_data
            sh_name_offset = len(shstrtab)

            # For the PoC, add a symbol to the start of the section
            symtab.append(
                struct.pack(
                    "<IIIBBH",
                    len(symstrtab),  # st_name
                    seg_addr,  # st_value
                    4,  # st_size
                    0,  # st_info = (bind=STB_LOCAL << 4) | (type=STT_NOTYPE)
                    0,  # st_other
                    len(sect_header),  # st_shndx
                )
            )
            symstrtab += f"start_{seg_addr:08x}".encode("ascii") + b"\0"

            shstrtab += seg_name.encode("ascii") + b"\0"
            shstrtab += b"\0" * (4 - (len(shstrtab) % 4))

            if seg_data is not None:
                print(f"Adding segment {seg_addr:#010x} at file offset {offset_data:#x} ({len(seg_data)} bytes)")

                # Craft program and section header
                prog_header.append(
                    struct.pack(
                        "<IIIIIIII",
                        1,  # p_type = PT_LOAD
                        offset_data,  # p_offset
                        seg_addr,  # p_vaddr
                        seg_addr,  # p_paddr
                        len(seg_data),  # p_filesz
                        len(seg_data),  # p_memsz
                        7,  # p_flags : PF_R=4 | PF_W=2 | PF_X=1
                        0,  # p_align
                    )
                )
                sect_header.append(
                    struct.pack(
                        "<IIIIIIIIII",
                        sh_name_offset,  # sh_name
                        1,  # sh_type = SHT_PROGBITS
                        7,  # sh_flags : SHF_WRITE=1 | SHF_ALLOC=2 | SHF_EXECINSTR=4
                        seg_addr,  # sh_addr
                        offset_data,  # sh_offset
                        len(seg_data),  # sh_size
                        0,  # sh_link
                        0,  # sh_info
                        0,  # sh_addralign
                        0,  # sh_entsize
                    )
                )
                file_data += seg_data
                offset_data += len(seg_data)
                offset_data = ((offset_data + 511) // 512) * 512
                file_data += b"\0" * (offset_data - base_offset_data - len(file_data))
                assert offset_data == base_offset_data + len(file_data)
            else:
                seg_size = seg_addr_end - seg_addr
                print(f"Adding uninitialized segment {seg_addr:#010x} ({seg_size} bytes)")
                prog_header.append(
                    struct.pack(
                        "<IIIIIIII",
                        1,  # p_type = PT_LOAD
                        offset_data,  # p_offset
                        seg_addr,  # p_vaddr
                        seg_addr,  # p_paddr
                        0,  # p_filesz
                        seg_size,  # p_memsz
                        6,  # p_flags : PF_R=4 | PF_W=2
                        0,  # p_align
                    )
                )
                sect_header.append(
                    struct.pack(
                        "<IIIIIIIIII",
                        sh_name_offset,  # sh_name
                        8,  # sh_type = SHT_NOBITS
                        3,  # sh_flags : SHF_WRITE=1 | SHF_ALLOC=2
                        seg_addr,  # sh_addr
                        offset_data,  # sh_offset
                        seg_size,  # sh_size
                        0,  # sh_link
                        0,  # sh_info
                        0,  # sh_addralign
                        0,  # sh_entsize
                    )
                )

        # Add .symtab section
        assert all(len(sym) == 0x10 for sym in symtab)
        sh_name_offset = len(shstrtab)
        shstrtab += b".symtab\0"
        shstrtab += b"\0" * (4 - (len(shstrtab) % 4))
        sect_header.append(
            struct.pack(
                "<IIIIIIIIII",
                sh_name_offset,  # sh_name
                2,  # sh_type = SHT_SYMTAB
                0,  # sh_flags
                0,  # sh_addr
                offset_data,  # sh_offset
                0x10 * len(symtab),  # sh_size
                len(sect_header) + 1,  # sh_link = linked string table
                len(symtab),  # sh_info
                0,  # sh_addralign
                0x10,  # sh_entsize
            )
        )
        file_data += b"".join(symtab)
        offset_data += 0x10 * len(symtab)
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b"\0" * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del symtab

        # Add .strtab section
        sh_name_offset = len(shstrtab)
        shstrtab += b".strtab\0"
        shstrtab += b"\0" * (4 - (len(shstrtab) % 4))
        sect_header.append(
            struct.pack(
                "<IIIIIIIIII",
                sh_name_offset,  # sh_name
                3,  # sh_type = SHT_STRTAB
                0,  # sh_flags
                0,  # sh_addr
                offset_data,  # sh_offset
                len(symstrtab),  # sh_size
                0,  # sh_link
                0,  # sh_info
                0,  # sh_addralign
                0,  # sh_entsize
            )
        )
        file_data += symstrtab
        offset_data += len(symstrtab)
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b"\0" * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del symstrtab

        # Add .shstrtab section
        sh_name_offset = len(shstrtab)
        shstrtab += b".shstrtab\0"
        shstrtab += b"\0" * (4 - (len(shstrtab) % 4))
        sect_header.append(
            struct.pack(
                "<IIIIIIIIII",
                sh_name_offset,  # sh_name
                3,  # sh_type = SHT_STRTAB
                0,  # sh_flags
                0,  # sh_addr
                offset_data,  # sh_offset
                len(shstrtab),  # sh_size
                0,  # sh_link
                0,  # sh_info
                0,  # sh_addralign
                0,  # sh_entsize
            )
        )
        file_data += shstrtab
        offset_data += len(shstrtab)  # Now offset_data is the offset to the section header
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b"\0" * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del shstrtab

        # Sanity checks
        num_ph_entries -= skipped_sections
        num_sh_entries -= skipped_sections
        assert all(len(ph) == 0x20 for ph in prog_header)
        assert all(len(sh) == 0x28 for sh in sect_header)
        assert len(prog_header) == num_ph_entries
        assert len(sect_header) == num_sh_entries

        # Craft the ELF header
        elf_header = bytes.fromhex("7f454c46010101000000000000000000") + struct.pack(
            "<HHIIIIIHHHHHH",
            2,  # e_type
            0x5D,  # e_machine = EM_ARCOMPACT
            1,  # e_version
            0,  # e_entry: the LMAC CPU starts at 0, the UMAC CPU at 0xc0080000
            0x34,  # e_phoff
            offset_data,  # e_shoff
            0,  # e_flags
            0x34,  # e_ehsize
            0x20,  # e_phentsize
            num_ph_entries,  # e_phnum
            0x28,  # e_shentsize
            num_sh_entries,  # e_shnum
            num_sh_entries - 1,  # e_shstrndx
        )
        assert len(elf_header) == 0x34

        # Add the program header and padding, the content, and the section header
        return b"".join(
            (
                elf_header,
                b"".join(prog_header),
                b"\0" * (base_offset_data - (0x34 + 0x20 * num_ph_entries)),
                file_data,
                b"".join(sect_header),
            )
        )


def craft_elf(ucode_path: Path, output_prefix: Optional[Path]) -> None:
    if output_prefix:
        out_dir = output_prefix.parent
        out_prefix_name = output_prefix.name
    else:
        out_dir = ucode_path.parent
        out_prefix_name = ucode_path.name

    for idx, fw in enumerate(IntelWifiFirmware.parse_all_file(ucode_path)):
        if idx > 0:
            print(f"---- Firmware #{idx} ----")
            out_idx_name = f".{idx}"
        else:
            out_idx_name = ""
        fw.print_header()

        init_segments = DataSegments()
        regular_segments = DataSegments()

        # Add hardware registers to both init and regular ELF files
        for segments in (init_segments, regular_segments):
            segments.add_uninitialized_segment(0x00A00000, 0x100000, "HW_00A00000")
            segments.add_uninitialized_segment(0xC0A00000, 0x100000, "HW_C0A00000")

        for entry in fw.entries:
            entry_type = int(entry.type_)

            if entry_type == UcodeTlvType.SEC_INIT:
                _, section = fw.decode_entry(entry)
                addr = section.addr
                size = len(section.data)
                print(f"Loading {addr:08x}..{addr + size:08x}: {size:#x}={size} bytes of Init ucode")
                init_segments.add_segment(addr, section.data)
            elif entry_type == UcodeTlvType.SEC_RT:
                _, section = fw.decode_entry(entry)
                addr = section.addr
                size = len(section.data)

                # Do not transmit signatures, which conflict with other segments
                if size == 4 and addr in (0xAAAABBBB, 0xFFFFCCCC):
                    print(f"Skipping {addr:08x}..{addr + size:08x}: separator (Regular ucode)")
                elif addr == 0 and size < 0x400:
                    print(f"Skipping {addr:08x}..{addr + size:08x}: maybe signature (Regular ucode)")
                else:
                    print(f"Loading {addr:08x}..{addr + size:08x}: {size:#x}={size} bytes of Regular ucode")
                    regular_segments.add_segment(addr, section.data)

        elf_path = out_dir / f"{out_prefix_name}{out_idx_name}.init.elf"
        print(f"Writing {elf_path} ...")
        elf_data = init_segments.to_elf()
        with elf_path.open("wb") as fp:
            fp.write(elf_data)

        elf_path = out_dir / f"{out_prefix_name}{out_idx_name}.regular.elf"
        print(f"Writing {elf_path} ...")
        elf_data = regular_segments.to_elf()
        with elf_path.open("wb") as fp:
            fp.write(elf_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Craft ELF file")
    parser.add_argument("ucode", type=Path, help="iwlwifi...ucode file")
    parser.add_argument("-o", "--out", type=Path, help="prefix for output files")
    args = parser.parse_args()

    craft_elf(args.ucode, args.out)
