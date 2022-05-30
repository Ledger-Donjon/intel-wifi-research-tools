# SPDX-License-Identifier: MIT

# Define exception vectors used in iwlwifi ARCompact firmware

# It is NOT the ARCompact IVT entries in QEMU from
# https://github.com/foss-for-synopsys-dwc-arc-processors/qemu/blob/93c024bc39914092d38563242ab55144013ff480/tests/tcg/arc/ivt.S
# but "Table 25 Exception vectors" and "Table 26 Exception Priorities and Vectors"
# in ARCompact Programmer's Reference, page 87: http://me.bios.io/images/d/dd/ARCompactISA_ProgrammersReference.pdf#page=87

EXCEPTION_VECTOR_OFFSETS = (
    (0x000, "Reset"),
    (0x008, "MemoryError"),
    (0x010, "InstructionError"),
    (0x018, "Interrupt03"),
    (0x020, "Interrupt04"),
    (0x028, "Interrupt05"),
    (0x030, "Interrupt06"),
    (0x038, "Interrupt07"),
    (0x040, "Interrupt08"),
    (0x048, "Interrupt09"),
    (0x050, "Interrupt10"),
    (0x058, "Interrupt11"),
    (0x060, "Interrupt12"),
    (0x068, "Interrupt13"),
    (0x070, "Interrupt14"),
    (0x078, "Interrupt15"),
    (0x080, "Interrupt16"),
    (0x088, "Interrupt17"),
    (0x090, "Interrupt18"),
    (0x098, "Interrupt19"),
    (0x0a0, "Interrupt20"),
    (0x0a8, "Interrupt21"),
    (0x0b0, "Interrupt22"),
    (0x0b8, "Interrupt23"),
    (0x0c0, "Interrupt24"),
    (0x0c8, "Interrupt25"),
    (0x0d0, "Interrupt26"),
    (0x0d8, "Interrupt27"),
    (0x0e0, "Interrupt28"),
    (0x0e8, "Interrupt29"),
    (0x0f0, "Interrupt30"),
    (0x0f8, "Interrupt31"),
    (0x100, "EV_MachineCheck"),
    (0x108, "EV_TLBMissI"),
    (0x110, "EV_TLBMissD"),
    (0x118, "EV_TLBProtV"),
    (0x120, "EV_PrivilegeV"),
    (0x128, "EV_Trap"),
    (0x130, "EV_Extension"),
)

ram = currentProgram.getAddressFactory().getAddressSpace("ram")

# Search for writing INT_VECTOR_BASE auxiliary register, in the firmware
last_addr_with_jump = None
for vector_base_addr, prefix in ((0, "ExcLow"), (0xc0080000, "ExcHigh")):
    # Clear everything in the range, to start clean
    clearListing(ram.getAddress(vector_base_addr), ram.getAddress(vector_base_addr + 0x138))

    for vector_offset, vector_name in EXCEPTION_VECTOR_OFFSETS:
        addr = ram.getAddress(vector_base_addr + vector_offset)
        wanted_name = "{}_{}".format(prefix, vector_name)

        # Check bytes
        first_bytes = tuple(getBytes(addr, 2))
        if first_bytes == (0x7e, 0x7e):
            # It is padding with traps, never consider these bytes!
            continue
        elif first_bytes == (0x20, 0x20):
            # Ok, it is a jump instruction!
            last_addr_with_jump = vector_base_addr + vector_offset
        elif first_bytes == (0xf1 - 0x100, 0xc0 - 0x100):
            # Ok, it is a push_s blink
            pass
        elif last_addr_with_jump == vector_base_addr + vector_offset - 8:
            # Start of function, right after a jump
            pass
        else:
            # print("Skip label {!r} at {!r} because bytes are ({:#04x}, {:#04x})".format(
            #     wanted_name, addr, first_bytes[0], first_bytes[1]))

            # Define code anyway
            disassemble(addr)
            continue

        current_sym = getSymbolAt(addr)
        if not current_sym or current_sym.name != wanted_name:
            print("Creating label {!r} at {!r} (was {!r})".format(wanted_name, addr, current_sym))
            createLabel(addr, wanted_name, True)  # makePrimary = True

        if getSymbolAt(addr).name != wanted_name:
            raise RuntimeError(
                "Unexpected name {!r} at {!r} (expected {!r})".format(
                    getSymbolAt(addr).name, addr, wanted_name
                )
            )

        # Create function at the given address
        print("Creating function {!r} at {!r} (sym {!r})".format(wanted_name, addr, current_sym))
        disassemble(addr)
        createFunction(addr, wanted_name)
