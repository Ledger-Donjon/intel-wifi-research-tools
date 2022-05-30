# SPDX-License-Identifier: MIT

# Define AUX registers in ARCompact MCU
import re

# Create AUXREGS memory space
auxregs = currentProgram.getAddressFactory().getAddressSpace("auxregs")

uint_t = ghidra.program.model.data.UnsignedIntegerDataType()

mem = currentProgram.getMemory()

if mem.getBlock(auxregs.getAddress(0)) is None:
    # Create a memory block to store AUX registers
    print("Creating a new mem block for AUX registers")
    mem.createUninitializedBlock("AUXREGS", auxregs.getAddress(0), 0x10000, False)
    mem.getBlock(auxregs.getAddress(0)).setPermissions(True, True, False)  # RW, no X

auxregs_block = mem.getBlock(auxregs.getAddress(0))
print(
    "AUX regs belong to mem block {!r}, perms={}".format(
        auxregs_block.name, auxregs_block.permissions
    )
)
assert auxregs_block.permissions == 6

# Symbols in ARCompact.pspec
KNOWN_AUXREGS = """
    <symbol name="STATUS" address="auxregs:0000"/>
    <symbol name="SEMAPHORE" address="auxregs:0004"/>
    <symbol name="LP_START" address="auxregs:0008"/>
    <symbol name="LP_END" address="auxregs:000C"/>
    <symbol name="IDENTITY" address="auxregs:0010"/>
    <symbol name="DEBUG" address="auxregs:0014"/>
    <symbol name="PC" address="auxregs:0018"/>
    <symbol name="ADCR" address="auxregs:001C"/>
    <symbol name="APCR" address="auxregs:0020"/>
    <symbol name="ACR" address="auxregs:0024"/>
    <symbol name="STATUS32" address="auxregs:0028"/>
    <symbol name="STATUS32_L1" address="auxregs:002C"/>
    <symbol name="STATUS32_L2" address="auxregs:0030"/>
    <symbol name="IVIC" address="auxregs:0040"/>
    <symbol name="CHE_MODE" address="auxregs:0044"/>
    <symbol name="MULHI" address="auxregs:0048"/>
    <symbol name="LOCKLINE" address="auxregs:004C"/>
    <symbol name="DMC_CODE_RAM" address="auxregs:0050"/>
    <symbol name="TAG_ADDR_MASK" address="auxregs:0054"/>
    <symbol name="TAG_DATA_MASK" address="auxregs:0058"/>
    <symbol name="LINE_LENGTH_MASK" address="auxregs:005C"/>
    <symbol name="DCCM_BASE" address="auxregs:0060"/>
    <symbol name="UNLOCKLINE" address="auxregs:0064"/>
    <symbol name="IC_RAM_ADDRESS" address="auxregs:0068"/>
    <symbol name="IC_TAG" address="auxregs:006C"/>
    <symbol name="IC_WP" address="auxregs:0070"/>
    <symbol name="IC_DATA" address="auxregs:0074"/>
    <symbol name="IC_PTAG" address="auxregs:0078"/>
    <symbol name="IC_PTAG_HI" address="auxregs:007C"/>
    <symbol name="COUNT0" address="auxregs:0084"/>
    <symbol name="CONTROL0" address="auxregs:0088"/>
    <symbol name="LIMIT0" address="auxregs:008C"/>
    <symbol name="PCPORT" address="auxregs:0090"/>
    <symbol name="INT_VECTOR_BASE" address="auxregs:0094"/>
    <symbol name="AUX_VBFDW_MODE" address="auxregs:0098"/>
    <symbol name="AUX_VBFDW_BM0" address="auxregs:009C"/>
    <symbol name="AUX_VBFDW_BM1" address="auxregs:00A0"/>
    <symbol name="AUX_VBFDW_ACCU" address="auxregs:00A4"/>
    <symbol name="AUX_VBFDW_OFST" address="auxregs:00A8"/>
    <symbol name="AUX_VBFDW_INTSTAT" address="auxregs:00AC"/>
    <symbol name="AUX_XMAC0_24" address="auxregs:00B0"/>
    <symbol name="AUX_XMAC1_24" address="auxregs:00B4"/>
    <symbol name="AUX_XMAC2_24" address="auxregs:00B8"/>
    <symbol name="AUX_FBF_STORE_16" address="auxregs:00BC"/>
    <symbol name="ERP_CTRL" address="auxregs:00FC"/>
    <symbol name="AUX_MACMODE" address="auxregs:0104"/>
    <symbol name="AUX_IRQ_LV12" address="auxregs:010C"/>
    <symbol name="AUX_XMAC0" address="auxregs:0110"/>
    <symbol name="AUX_XMAC1" address="auxregs:0114"/>
    <symbol name="AUX_XMAC2" address="auxregs:0118"/>
    <symbol name="DC_IVDC" address="auxregs:011C"/>
    <symbol name="DC_CTRL" address="auxregs:0120"/>
    <symbol name="DC_LDL" address="auxregs:0124"/>
    <symbol name="DC_IVDL" address="auxregs:0128"/>
    <symbol name="DC_FLSH" address="auxregs:012C"/>
    <symbol name="DC_FLDL" address="auxregs:0130"/>
    <symbol name="DC_STARTR" address="auxregs:0134"/>
    <symbol name="DC_ENDR" address="auxregs:0138"/>
    <symbol name="SWSTAT" address="auxregs:015C"/>
    <symbol name="DC_RAM_ADDR" address="auxregs:0160"/>
    <symbol name="DC_TAG" address="auxregs:0164"/>
    <symbol name="DC_WP" address="auxregs:0168"/>
    <symbol name="DC_DATA" address="auxregs:016C"/>
    <symbol name="DC_PTAG" address="auxregs:0170"/>
    <symbol name="AUX_VOLATILE" address="auxregs:0178"/>
    <symbol name="DC_PTAG_HI" address="auxregs:017C"/>
    <symbol name="BCR_VER" address="auxregs:0180"/>
    <symbol name="DCCM_BASE_BUILD" address="auxregs:0184"/>
    <symbol name="CRC_BUILD" address="auxregs:0188"/>
    <symbol name="BTA_LINK_BUILD" address="auxregs:018C"/>
    <symbol name="VBFDW_BUILD" address="auxregs:0190"/>
    <symbol name="EA_BUILD" address="auxregs:0194"/>
    <symbol name="DATASPACE" address="auxregs:0198"/>
    <symbol name="MEMSUBSYS" address="auxregs:019C"/>
    <symbol name="VECBASE_AC_BUILD" address="auxregs:01A0"/>
    <symbol name="PERIBASE_ADDR" address="auxregs:01A4"/>
    <symbol name="DATA_UNCACHED_BUILD" address="auxregs:01A8"/>
    <symbol name="FP_BUILD" address="auxregs:01AC"/>
    <symbol name="DPFP_BUILD" address="auxregs:01B0"/>
    <symbol name="MPU_BUILD" address="auxregs:01B4"/>
    <symbol name="RF_BUILD" address="auxregs:01B8"/>
    <symbol name="MMU_BUILD" address="auxregs:01BC"/>
    <symbol name="VECBASE_BUILD" address="auxregs:01C4"/>
    <symbol name="D_CACHE_BUILD" address="auxregs:01C8"/>
    <symbol name="MADI_BUILD" address="auxregs:01CC"/>
    <symbol name="DCCM_BUILD" address="auxregs:01D0"/>
    <symbol name="TIMER_BUILD" address="auxregs:01D4"/>
    <symbol name="AP_BUILD" address="auxregs:01D8"/>
    <symbol name="I_CACHE_BUILD" address="auxregs:01DC"/>
    <symbol name="ICCM_BUILD" address="auxregs:01E0"/>
    <symbol name="DSPRAM_BUILD" address="auxregs:01E4"/>
    <symbol name="MAC_BUILD" address="auxregs:01E8"/>
    <symbol name="MULTIPLY_BUILD" address="auxregs:01EC"/>
    <symbol name="SWAP_BUILD" address="auxregs:01F0"/>
    <symbol name="NORM_BUILD" address="auxregs:01F4"/>
    <symbol name="MINMAX_BUILD" address="auxregs:01F8"/>
    <symbol name="BARREL_BUILD" address="auxregs:01FC"/>
    <symbol name="AX0" address="auxregs:0200"/>
    <symbol name="AX1" address="auxregs:0204"/>
    <symbol name="AX2" address="auxregs:0208"/>
    <symbol name="AX3" address="auxregs:020C"/>
    <symbol name="AY0" address="auxregs:0210"/>
    <symbol name="AY1" address="auxregs:0214"/>
    <symbol name="AY2" address="auxregs:0218"/>
    <symbol name="AY3" address="auxregs:021C"/>
    <symbol name="MX00" address="auxregs:0220"/>
    <symbol name="MX01" address="auxregs:0224"/>
    <symbol name="MX10" address="auxregs:0228"/>
    <symbol name="MX11" address="auxregs:022C"/>
    <symbol name="MX20" address="auxregs:0230"/>
    <symbol name="MX21" address="auxregs:0234"/>
    <symbol name="MX30" address="auxregs:0238"/>
    <symbol name="MX31" address="auxregs:023C"/>
    <symbol name="MY00" address="auxregs:0240"/>
    <symbol name="MY01" address="auxregs:0244"/>
    <symbol name="MY10" address="auxregs:0248"/>
    <symbol name="MY11" address="auxregs:024C"/>
    <symbol name="MY20" address="auxregs:0250"/>
    <symbol name="MY21" address="auxregs:0254"/>
    <symbol name="MY30" address="auxregs:0258"/>
    <symbol name="MY31" address="auxregs:025C"/>
    <symbol name="XYCONFIG" address="auxregs:0260"/>
    <symbol name="BURSTSYS" address="auxregs:0264"/>
    <symbol name="BURSTXYM" address="auxregs:0268"/>
    <symbol name="BURSTSZ" address="auxregs:026C"/>
    <symbol name="BURSTVAL" address="auxregs:0270"/>
    <symbol name="XYLSBASEX" address="auxregs:0274"/>
    <symbol name="XYLSBASEY" address="auxregs:0278"/>
    <symbol name="AUX_XMACLW_H" address="auxregs:027C"/>
    <symbol name="AUX_XMACLW_L" address="auxregs:0280"/>
    <symbol name="SE_CTRL" address="auxregs:0284"/>
    <symbol name="SE_STATUS" address="auxregs:0288"/>
    <symbol name="SE_ERR" address="auxregs:028C"/>
    <symbol name="SE_EADR" address="auxregs:0290"/>
    <symbol name="SE_SPC" address="auxregs:0294"/>
    <symbol name="SDM_BASE" address="auxregs:0298"/>
    <symbol name="SCM_BASE" address="auxregs:029C"/>
    <symbol name="SE_DBG_CTRL" address="auxregs:02A0"/>
    <symbol name="SE_DBG_DATA0" address="auxregs:02A4"/>
    <symbol name="SE_DBG_DATA1" address="auxregs:02A8"/>
    <symbol name="SE_DBG_DATA2" address="auxregs:02AC"/>
    <symbol name="SE_DBG_DATA3" address="auxregs:02B0"/>
    <symbol name="SE_WATCH" address="auxregs:02B4"/>
    <symbol name="BPU_BUILD" address="auxregs:0300"/>
    <symbol name="ISA_CONFIG_BUILD" address="auxregs:0304"/>
    <symbol name="ERP_BUILD" address="auxregs:031C"/>
    <symbol name="FP_V2_BUILD" address="auxregs:0320"/>
    <symbol name="AGU_BUILD" address="auxregs:0330"/>
    <symbol name="SLC_BUILD" address="auxregs:0338"/>
    <symbol name="CLUSTER_BUILD" address="auxregs:033C"/>
    <symbol name="LPB_BUILD" address="auxregs:03A4"/>
    <symbol name="RTT_BUILD" address="auxregs:03C8"/>
    <symbol name="IRQ_BUILD" address="auxregs:03CC"/>
    <symbol name="HWP_BUILD" address="auxregs:03D0"/>
    <symbol name="PCT_BUILD" address="auxregs:03D4"/>
    <symbol name="CC_BUILD" address="auxregs:03D8"/>
    <symbol name="PM_BUILD" address="auxregs:03DC"/>
    <symbol name="SCQ_SWITCH_BUILD" address="auxregs:03E0"/>
    <symbol name="VRAPTOR_BUILD" address="auxregs:03E4"/>
    <symbol name="DMA_CONFIG" address="auxregs:03E8"/>
    <symbol name="SIMD_CONFIG" address="auxregs:03EC"/>
    <symbol name="VLC_BUILD" address="auxregs:03F0"/>
    <symbol name="SIMD_DMA_BUILD" address="auxregs:03F4"/>
    <symbol name="IFETCH_QUEUE_BUILD" address="auxregs:03F8"/>
    <symbol name="SMART_BUILD" address="auxregs:03FC"/>
    <symbol name="COUNT1" address="auxregs:0400"/>
    <symbol name="CONTROL1" address="auxregs:0404"/>
    <symbol name="LIMIT1" address="auxregs:0408"/>
    <symbol name="AUX_IRQ_LEV" address="auxregs:0800"/>
    <symbol name="AUX_IRQ_HINT" address="auxregs:0804"/>
    <symbol name="AUX_INTER_CORE_INT" address="auxregs:0808"/>
    <symbol name="AUX_ICCM" address="auxregs:0820"/>
    <symbol name="AES_AUX_0" address="auxregs:0840"/>
    <symbol name="AES_AUX_1" address="auxregs:0844"/>
    <symbol name="AES_AUX_2" address="auxregs:0848"/>
    <symbol name="AES_CRYPT_MODE" address="auxregs:084C"/>
    <symbol name="AES_AUXS" address="auxregs:0850"/>
    <symbol name="AES_AUXI" address="auxregs:0854"/>
    <symbol name="AES_AUX_3" address="auxregs:0858"/>
    <symbol name="AES_AUX_4" address="auxregs:085C"/>
    <symbol name="ARITH_CTL_AUX" address="auxregs:0860"/>
    <symbol name="DES_AUX" address="auxregs:0864"/>
    <symbol name="AP_AMV0" address="auxregs:0880"/>
    <symbol name="AP_AMM0" address="auxregs:0884"/>
    <symbol name="AP_AC0" address="auxregs:0888"/>
    <symbol name="AP_AMV1" address="auxregs:088C"/>
    <symbol name="AP_AMM1" address="auxregs:0890"/>
    <symbol name="AP_AC1" address="auxregs:0894"/>
    <symbol name="AP_AMV2" address="auxregs:0898"/>
    <symbol name="AP_AMM2" address="auxregs:089C"/>
    <symbol name="AP_AC2" address="auxregs:08A0"/>
    <symbol name="AP_AMV3" address="auxregs:08A4"/>
    <symbol name="AP_AMM3" address="auxregs:08A8"/>
    <symbol name="AP_AC3" address="auxregs:08AC"/>
    <symbol name="AP_AMV4" address="auxregs:08B0"/>
    <symbol name="AP_AMM4" address="auxregs:08B4"/>
    <symbol name="AP_AC4" address="auxregs:08B8"/>
    <symbol name="AP_AMV5" address="auxregs:08BC"/>
    <symbol name="AP_AMM5" address="auxregs:08C0"/>
    <symbol name="AP_AC5" address="auxregs:08C4"/>
    <symbol name="AP_AMV6" address="auxregs:08C8"/>
    <symbol name="AP_AMM6" address="auxregs:08CC"/>
    <symbol name="AP_AC6" address="auxregs:08D0"/>
    <symbol name="AP_AMV7" address="auxregs:08D4"/>
    <symbol name="AP_AMM7" address="auxregs:08D8"/>
    <symbol name="AP_AC7" address="auxregs:08DC"/>
    <symbol name="FPU_STATUS" address="auxregs:0C00"/>
    <symbol name="DPFP_1L" address="auxregs:0C04"/>
    <symbol name="DPFP_1H" address="auxregs:0C08"/>
    <symbol name="DPFP_2L" address="auxregs:0C0C"/>
    <symbol name="DPFP_2H" address="auxregs:0C10"/>
    <symbol name="DPFP_STATUS" address="auxregs:0C14"/>
    <symbol name="ERET" address="auxregs:1000"/>
    <symbol name="ERBTA" address="auxregs:1004"/>
    <symbol name="ERSTATUS" address="auxregs:1008"/>
    <symbol name="ECR" address="auxregs:100C"/>
    <symbol name="EFA" address="auxregs:1010"/>
    <symbol name="MMU_TLBPD0" address="auxregs:1014"/>
    <symbol name="MMU_TLBPD1" address="auxregs:1018"/>
    <symbol name="MMU_TLBINDEX" address="auxregs:101C"/>
    <symbol name="MMU_TLBCOMMAND" address="auxregs:1020"/>
    <symbol name="MMU_PID_and_MPUEN" address="auxregs:1024"/>
    <symbol name="ICAUSE1" address="auxregs:1028"/>
    <symbol name="ICAUSE2" address="auxregs:102C"/>
    <symbol name="AUX_IENABLE" address="auxregs:1030"/>
    <symbol name="AUX_ITRIGGER" address="auxregs:1034"/>
    <symbol name="XPU" address="auxregs:1040"/>
    <symbol name="BTA" address="auxregs:1048"/>
    <symbol name="BTA_L1" address="auxregs:104C"/>
    <symbol name="BTA_L2" address="auxregs:1050"/>
    <symbol name="AUX_IRQ_PULSE_CANCEL" address="auxregs:1054"/>
    <symbol name="AUX_IRQ_PENDING" address="auxregs:1058"/>
    <symbol name="MMU_SCRATCH_DATA0" address="auxregs:1060"/>
    <symbol name="MPUIC" address="auxregs:1080"/>
    <symbol name="MPUFA" address="auxregs:1084"/>
    <symbol name="MPURDB0" address="auxregs:1088"/>
    <symbol name="MPURDP0" address="auxregs:108C"/>
    <symbol name="MPURDB1" address="auxregs:1090"/>
    <symbol name="MPURDP1" address="auxregs:1094"/>
    <symbol name="MPURDB2" address="auxregs:1098"/>
    <symbol name="MPURDP2" address="auxregs:109C"/>
    <symbol name="MPURDB3" address="auxregs:10A0"/>
    <symbol name="MPURDP3" address="auxregs:10A4"/>
    <symbol name="MPURDB4" address="auxregs:10A8"/>
    <symbol name="MPURDP4" address="auxregs:10AC"/>
    <symbol name="MPURDB5" address="auxregs:10B0"/>
    <symbol name="MPURDP5" address="auxregs:10B4"/>
    <symbol name="MPURDB6" address="auxregs:10B8"/>
    <symbol name="MPURDP6" address="auxregs:10BC"/>
    <symbol name="MPURDB7" address="auxregs:10C0"/>
    <symbol name="MPURDP7" address="auxregs:10C4"/>
    <symbol name="MPURDB8" address="auxregs:10C8"/>
    <symbol name="MPURDP8" address="auxregs:10CC"/>
    <symbol name="MPURDB9" address="auxregs:10D0"/>
    <symbol name="MPURDP9" address="auxregs:10D4"/>
    <symbol name="MPURDB10" address="auxregs:10D8"/>
    <symbol name="MPURDP10" address="auxregs:10DC"/>
    <symbol name="MPURDB11" address="auxregs:10E0"/>
    <symbol name="MPURDP11" address="auxregs:10E4"/>
    <symbol name="MPURDB12" address="auxregs:10E8"/>
    <symbol name="MPURDP12" address="auxregs:10EC"/>
    <symbol name="MPURDB13" address="auxregs:10F0"/>
    <symbol name="MPURDP13" address="auxregs:10F4"/>
    <symbol name="MPURDB14" address="auxregs:10F8"/>
    <symbol name="MPURDP14" address="auxregs:10FC"/>
    <symbol name="MPURDB15" address="auxregs:1100"/>
    <symbol name="MPURDP15" address="auxregs:1104"/>
    <symbol name="PM_STATUS" address="auxregs:1140"/>
    <symbol name="WAKE" address="auxregs:1144"/>
    <symbol name="DVFS_PERFORMANCE" address="auxregs:1148"/>
    <symbol name="PWR_CTRL" address="auxregs:114C"/>
    <symbol name="LPB_CTRL" address="auxregs:1220"/>
    <symbol name="SMART_CONTROL" address="auxregs:1C00"/>
"""

# Add custom registers from reverse engineering
# and from "IDA Pro/cfg/arc.cfg"
# and from https://elixir.bootlin.com/linux/v5.12/source/arch/arc/include/asm/cache.h#L74
# ... and in Linux: grep ARC_REG_  => include/asm/arcregs.h
# https://elixir.bootlin.com/linux/v5.12/source/arch/arc/include/asm/arcregs.h
KNOWN_AUXREGS += """
    <symbol name="UNKNOWN_AUX_0E" address="auxregs:0038"/>
"""

for line in KNOWN_AUXREGS.splitlines():
    if not line:
        continue
    matches = re.match(
        r'^ *<symbol name="([0-9A-Za-z_]+)" address="auxregs:([0-9A-F]+)"/>$', line
    )
    if not matches:
        raise RuntimeError("Unable to parse line {!r}".format(line))
    name = matches.group(1)
    addr = auxregs.getAddress(int(matches.group(2), 16))

    current_name = getSymbolAt(addr)
    if not current_name or current_name.name != name:
        print("Creating label {!r} at {!r} (was {!r})".format(name, addr, current_name))
        createLabel(addr, name, True)

    if getSymbolAt(addr).name != name:
        raise RuntimeError(
            "Unexpected name {!r} at {!r} (expected {!r})".format(
                getSymbolAt(addr).name, addr, name
            )
        )

    current_type = getDataAt(addr)
    if current_type is None:
        print("Setting type of {!r} at {!r} to {!r}".format(name, addr, uint_t))
        createData(addr, uint_t)

    if getDataAt(addr).toString() != "uint ??":  # "??" because undefined data
        raise RuntimeError("Unexpected type {!r} at {!r}".format(getDataAt(addr), addr))
