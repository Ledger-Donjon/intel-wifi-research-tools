#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Parse Intel Wi-Fi firmware

In Linux kernel, the firmware is parsed by iwl_parse_tlv_firmware:
https://github.com/torvalds/linux/blob/v5.11/drivers/net/wireless/intel/iwlwifi/iwl-drv.c#L554

References:
- For up-to-date structures, the linux-next repository can help:
  https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/tree/drivers/net/wireless/intel/iwlwifi
  Structures for parsing a firmware are located in drivers/net/wireless/intel/iwlwifi/fw/file.h
- For macOS version: https://github.com/OpenIntelWireless/itlwm
  (archived project) https://github.com/AppleIntelWifi/adapter

Wi-Fi command codes are defined:
- in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlwifi/fw/api
- in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16
- in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/iwlegacy/commands.h?id=dbdac2b581811e1f2a573454451136c2497de4fc
- in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/iwlegacy/iwl-commands.h?id=7f8e12238049b0e5398e77cdf15f95a41077841f
- in https://github.com/OpenIntelWireless/itlwm/blob/v2.1.0/itlwm/hal_iwm/if_iwmreg.h

Dependency: construct>=2.10
"""
import argparse
import enum
import hashlib
import io
from pathlib import Path
import sys
from typing import Any, BinaryIO, Generator, List, Mapping, Optional, TextIO, Tuple, Type, Union

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.hashes

from construct import (
    Array,
    Bytes,
    Const,
    Container,
    Enum,
    GreedyBytes,
    GreedyRange,
    Hex,
    Int8ul,
    Int16ul,
    Int32ul,
    Int64ul,
    PaddedString,
    Rebuild,
    Struct,
    len_,
    this,
)


@enum.unique
class CalibCfg(enum.IntFlag):
    """enum iwl_calib_cfg (prefix IWL_CALIB_CFG_)"""

    XTAL_IDX = 1
    TEMPERATURE_IDX = 2
    VOLTAGE_READ_IDX = 4
    PAPD_IDX = 8
    TX_PWR_IDX = 0x10
    DC_IDX = 0x20
    BB_FILTER_IDX = 0x40
    LO_LEAKAGE_IDX = 0x80
    TX_IQ_IDX = 0x100
    TX_IQ_SKEW_IDX = 0x200
    RX_IQ_IDX = 0x400
    RX_IQ_SKEW_IDX = 0x800
    SENSITIVITY_IDX = 0x1000
    CHAIN_NOISE_IDX = 0x2000
    DISCONNECTED_ANT_IDX = 0x4000
    ANT_COUPLING_IDX = 0x8000
    DAC_IDX = 0x10000
    ABS_IDX = 0x20000
    AGC_IDX = 0x40000


@enum.unique
class CfgMacType(enum.IntEnum):
    """Macros with prefix IWL_CFG_MAC_TYPE_"""

    PU = 0x31
    PNJ_TH = 0x32  # Both PNJ and TH
    QU = 0x33
    QUZ = 0x35
    QNJ = 0x36
    SO = 0x37
    SNJ = 0x42
    SOF = 0x43
    MA = 0x44
    BZ = 0x46
    GL = 0x47

    @classmethod
    def from_name(cls, name: str) -> "CfgMacType":
        if name in {"PNJ", "TH"}:
            return cls.PNJ_TH
        return getattr(cls, name)


@enum.unique
class CfgRfType(enum.IntEnum):
    """Macros with prefix IWL_CFG_RF_TYPE_"""

    TH_JF2 = 0x105  # Both TH and JF2
    TH1_JF1 = 0x108  # Both TH1 and JF1
    HR2 = 0x10A
    HR1 = 0x10C
    GF = 0x10D
    MR = 0x110
    MS = 0x111
    FM = 0x112

    @classmethod
    def from_name(cls, name: str) -> "CfgRfType":
        if name in {"TH", "JF2"}:
            return cls.TH_JF2
        if name in {"TH1", "JF1"}:
            return cls.TH1_JF1
        return getattr(cls, name)


@enum.unique
class FwDbgRegOperator(enum.IntEnum):
    """enum iwl_fw_dbg_reg_operator (no prefix)"""

    CSR_ASSIGN = 0
    CSR_SETBIT = 1
    CSR_CLEARBIT = 2
    PRPH_ASSIGN = 3
    PRPH_SETBIT = 4
    PRPH_CLEARBIT = 5
    INDIRECT_ASSIGN = 6
    INDIRECT_SETBIT = 7
    INDIRECT_CLEARBIT = 8
    PRPH_BLOCKBIT = 9


@enum.unique
class FwIniAllocationId(enum.IntEnum):
    """enum iwl_fw_ini_allocation_id (prefix IWL_FW_INI_ALLOCATION_ID_)"""

    INVALID = 0
    DBGC1 = 1
    DBGC2 = 2
    DBGC3 = 3
    DBGC4 = 4
    FW_DUMP = 5
    USER_DEFINED = 6

    @classmethod
    def from_name(cls, name: str) -> "FwIniAllocationId":
        if name == "SDFX":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b87384af8d6701c0fe6ffbe885feb200150b1ee4  # noqa
            # and later replaced with INTERNAL
            return cls.DBGC4
        if name == "INTERNAL":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e75bc5f3f110aa6c4c372e574bd2c37a8cad495f  # noqa
            # and later replaced with DBGC4
            return cls.DBGC4
        return getattr(cls, name)


@enum.unique
class FwIniBufferLocation(enum.IntEnum):
    """enum iwl_fw_ini_buffer_location (prefix IWL_FW_INI_LOCATION_)"""

    INVALID = 0
    SRAM_PATH = 1
    DRAM_PATH = 2
    NPK_PATH = 3

    @classmethod
    def from_name(cls, name: str) -> "FwIniBufferLocation":
        if name == "SRAM_INVALID":
            # Rename in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=56ea8e3b4ef6a319ac8297bc50f6909dccc684ec  # noqa
            return cls.INVALID
        return getattr(cls, name)


@enum.unique
class FwIniDbgDomain(enum.IntEnum):
    """enum iwl_fw_ini_dbg_domain (prefix IWL_FW_INI_DBG_DOMAIN_)"""

    ALWAYS_ON = 0
    REPORT_PS = 1


@enum.unique
class FwIniRegionDeviceMemorySubtype(enum.IntEnum):
    """enum iwl_fw_ini_region_device_memory_subtype (prefix IWL_FW_INI_REGION_DEVICE_MEMORY_SUBTYPE_)"""

    HW_SMEM = 1
    UNKNOWN_2 = 2  # Seen in iwlwifi-Qu-c0-jf-b0-71.ucode 71.058653f6.0 for "sw_smem"
    UNKNOWN_3 = 3  # Seen in iwlwifi-Qu-c0-jf-b0-71.ucode 71.058653f6.0 for "chmem"
    UNKNOWN_4 = 4  # Seen in iwlwifi-Qu-c0-jf-b0-71.ucode 71.058653f6.0 for "dccm_umac"
    UMAC_ERROR_TABLE = 5
    UNKNOWN_6 = 6  # Seen in iwlwifi-Qu-c0-jf-b0-71.ucode 71.058653f6.0 for "dccm_lmac1"
    LMAC_1_ERROR_TABLE = 7
    UNKNOWN_9 = 9  # Seen in iwlwifi-Qu-c0-jf-b0-71.ucode 71.058653f6.0 for "dccm_lmac2"
    LMAC_2_ERROR_TABLE = 10
    UNKNOWN_13 = 13  # Seen in WiFi-22.130.0-Driver64-Win10-Win11.exe for "dccm_tcm1"
    TCM_1_ERROR_TABLE = 14
    UNKNOWN_15 = 15  # Seen in WiFi-22.130.0-Driver64-Win10-Win11.exe for "dccm_tcm2"
    TCM_2_ERROR_TABLE = 16
    UNKNOWN_17 = 17  # Seen in WiFi-22.130.0-Driver64-Win10-Win11.exe for "dccm_rcm1"
    RCM_1_ERROR_TABLE = 18
    UNKNOWN_19 = 19  # Seen in WiFi-22.130.0-Driver64-Win10-Win11.exe for "dccm_rcm2"
    RCM_2_ERROR_TABLE = 20


@enum.unique
class OldFwIniRegionType(enum.IntEnum):
    """old enum iwl_fw_ini_region_type (prefix IWL_FW_INI_REGION_)

    Commit https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c9fe75e9f347044fda99a0da9c61983b153b8ed9  # noqa
    introduced new values, without renaming the enum
    """

    INVALID = 0
    DEVICE_MEMORY = 1
    PERIPHERY_MAC = 2
    PERIPHERY_PHY = 3
    PERIPHERY_AUX = 4
    DRAM_BUFFER = 5
    DRAM_IMR = 6
    INTERNAL_BUFFER = 7
    TXF = 8
    RXF = 9
    PAGING = 10
    CSR = 11
    NOTIFICATION = 12
    DHC = 13
    LMAC_ERROR_TABLE = 14
    UMAC_ERROR_TABLE = 15


@enum.unique
class FwIniRegionType(enum.IntEnum):
    """enum iwl_fw_ini_region_type (prefix IWL_FW_INI_REGION_)"""

    INVALID = 0
    TLV = 1
    INTERNAL_BUFFER = 2
    DRAM_BUFFER = 3
    TXF = 4
    RXF = 5
    LMAC_ERROR_TABLE = 6
    UMAC_ERROR_TABLE = 7
    RSP_OR_NOTIF = 8
    DEVICE_MEMORY = 9
    PERIPHERY_MAC = 10
    PERIPHERY_PHY = 11
    PERIPHERY_AUX = 12
    PAGING = 13
    CSR = 14
    DRAM_IMR = 15
    PCI_IOSF_CONFIG = 16
    SPECIAL_DEVICE_MEMORY = 17
    DBGI_SRAM = 18
    PERIPHERY_MAC_RANGE = 19  # Seen in iwlwifi-ty-a0-gf-a0-84.ucode__2023-09-21__81.8e5c544c.0 as "prph_mac_range"
    PERIPHERY_PHY_RANGE = 20
    PERIPHERY_SNPS_DPHYIP = 21


@enum.unique
class UcodeTlvApi(enum.IntEnum):
    """enum iwl_ucode_tlv_api (prefix IWL_UCODE_TLV_API_)"""

    WOWLAN_CONFIG_TID = 0
    CAPA_EXTENDED_BEACON = 1
    BT_COEX_SPLIT = 3
    CSA_FLOW = 4
    DISABLE_STA_TX = 5
    LMAC_SCAN = 6
    SF_NO_DUMMY_NOTIF = 7
    FRAGMENTED_SCAN = 8
    WIFI_MCC_UPDATE = 9
    HDC_PHASE_0 = 10
    TX_POWER_DEV = 11
    BASIC_DWELL = 13
    WIDE_CMD_HDR = 14
    SCD_CFG = 15
    SINGLE_SCAN_EBS = 16
    ASYNC_DTM = 17
    LQ_SS_PARAMS = 18
    STATS_V10 = 19
    NEW_VERSION = 20
    EXT_SCAN_PRIORITY = 24
    TX_POWER_CHAIN = 27
    SCAN_TSF_REPORT = 28
    TKIP_MIC_KEYS = 29
    STA_TYPE = 30
    NAN2_VER2 = 31
    ADAPTIVE_DWELL = 32
    OCE = 33
    NEW_BEACON_TEMPLATE = 34
    NEW_RX_STATS = 35
    WOWLAN_KEY_MATERIAL = 36
    COEX_ATS_EXTERNAL = 37
    QUOTA_LOW_LATENCY = 38
    DEPRECATE_TTAK = 41
    ADAPTIVE_DWELL_V2 = 42
    FRAG_EBS = 44
    REDUCE_TX_POWER = 45
    SHORT_BEACON_NOTIF = 46
    BEACON_FILTER_V4 = 47
    REGULATORY_NVM_INFO = 48
    FTM_NEW_RANGE_REQ = 49
    SCAN_OFFLOAD_CHANS = 50
    MBSSID_HE = 52
    WOWLAN_TCP_SYN_WAKE = 53
    FTM_RTT_ACCURACY = 54
    SAR_TABLE_VER = 55
    REDUCED_SCAN_CONFIG = 56
    ADWELL_HB_DEF_N_AP = 57
    SCAN_EXT_CHAN_VER = 58
    BAND_IN_RX_DATA = 59


@enum.unique
class UcodeTlvCapa(enum.IntEnum):
    """enum iwl_ucode_tlv_capa (prefix IWL_UCODE_TLV_CAPA_)"""

    D0I3_SUPPORT = 0
    LAR_SUPPORT = 1
    UMAC_SCAN = 2
    BEAMFORMER = 3
    TOF_SUPPORT = 5
    TDLS_SUPPORT = 6
    TXPOWER_INSERTION_SUPPORT = 8
    DS_PARAM_SET_IE_SUPPORT = 9
    WFA_TPC_REP_IE_SUPPORT = 10
    QUIET_PERIOD_SUPPORT = 11
    DQA_SUPPORT = 12
    TDLS_CHANNEL_SWITCH = 13
    CNSLDTD_D3_D0_IMG = 17
    HOTSPOT_SUPPORT = 18
    DC2DC_CONFIG_SUPPORT = 19
    CSUM_SUPPORT = 21
    RADIO_BEACON_STATS = 22
    P2P_SCM_UAPSD = 26
    BT_COEX_PLCR = 28
    LAR_MULTI_MCC = 29
    BT_COEX_RRC = 30
    GSCAN_SUPPORT = 31
    NAN_SUPPORT = 34  # not defined in Linux driver, but found in https://github.com/OpenIntelWireless/itlwm/blob/v2.0.0/itlwm/hal_iwx/if_iwxreg.h  # noqa
    UMAC_UPLOAD = 35
    SOC_LATENCY_SUPPORT = 37
    STA_PM_NOTIF = 38
    BINDING_CDB_SUPPORT = 39
    CDB_SUPPORT = 40
    D0I3_END_FIRST = 41
    TLC_OFFLOAD = 43
    DYNAMIC_QUOTA = 44
    COEX_SCHEMA_2 = 45
    CHANNEL_SWITCH_CMD = 46
    FTM_CALIBRATED = 47
    ULTRA_HB_CHANNELS = 48
    CS_MODIFY = 49
    SET_LTR_GEN2 = 50
    SET_PPAG = 52
    TAS_CFG = 53
    SESSION_PROT_CMD = 54
    PROTECTED_TWT = 56
    FW_RESET_HANDSHAKE = 57
    PASSIVE_6GHZ_SCAN = 58
    HIDDEN_6GHZ_SCAN = 59
    BROADCAST_TWT = 60
    COEX_HIGH_PRIO = 61
    RFIM_SUPPORT = 62
    BAID_ML_SUPPORT = 63
    EXTENDED_DTS_MEASURE = 64
    SHORT_PM_TIMEOUTS = 65
    BT_MPLUT_SUPPORT = 67
    MULTI_QUEUE_RX_SUPPORT = 68
    CSA_AND_TBTT_OFFLOAD = 70
    BEACON_ANT_SELECTION = 71
    BEACON_STORING = 72
    LAR_SUPPORT_V3 = 73
    CT_KILL_BY_FW = 74
    TEMP_THS_REPORT_SUPPORT = 75
    CTDP_SUPPORT = 76
    USNIFFER_UNIFIED = 77
    LMAC_UPLOAD = 79
    EXTEND_SHARED_MEM_CFG = 80
    LQM_SUPPORT = 81
    TX_POWER_ACK = 84
    # LED_CMD_SUPPORT = 86  # This value was updated in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4ef66965ce2f4d1c94b62025d35b2bd69d3f3889  # noqa
    D3_DEBUG = 87
    LED_CMD_SUPPORT = 88
    MCC_UPDATE_11AX_SUPPORT = 89
    CSI_REPORTING = 90
    DBG_SUSPEND_RESUME_CMD_SUPP = 92
    DBG_BUF_ALLOC_CMD_SUPP = 93
    MLME_OFFLOAD = 96
    PSC_CHAN_SUPPORT = 98
    BIGTK_SUPPORT = 100
    # RFIM_SUPPORT = 102  # This value was updated in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9da090cdbcfa1ef864bfcbad9ad7e18691395867  # noqa
    DRAM_FRAG_SUPPORT = 104
    DUMP_COMPLETE_SUPPORT = 105

    @classmethod
    def from_name(cls, name: str) -> "UcodeTlvCapa":
        if name == "LAR_SUPPORT_V2":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=47fe2f8ed5ebe76411285994619f71d22519d550
            return cls.LAR_SUPPORT_V3
        if name == "P2P_STANDALONE_UAPSD":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c5241b0c8c0bb2bfd69effaa81e30fa26a16adda
            return cls.P2P_SCM_UAPSD

        return getattr(cls, name)


@enum.unique
class UcodeTlvFlag(enum.IntEnum):
    """enum iwl_ucode_tlv_flag (prefix IWL_UCODE_TLV_FLAGS_)"""

    PAN = 0
    NEWSCAN = 1
    MFP = 2  # Management Frame Protection (802.11w)
    P2P = 3
    DW_BC_TABLE = 4
    NEWBT_COEX = 5
    PM_CMD_SUPPORT = 6
    SHORT_BL = 7  # Short black list
    RX_ENERGY_API = 8
    TIME_EVENT_API_V2 = 9
    D3_6_IPV6_ADDRS = 10
    BF_UPDATED = 11  # New beacon filtering command
    NO_BASIC_SSID = 12
    D3_CONTINUITY_API = 14
    NEW_NSOFFL_SMALL = 15
    NEW_NSOFFL_LARGE = 16
    SCHED_SCAN = 17  # Scheduled Scan
    STA_KEY_CMD = 19
    DEVICE_PS_CMD = 20
    P2P_PM = 21
    BSS_P2P_PS_DCM = 22
    BSS_P2P_PS_SCM = 23
    UAPSD_SUPPORT = 24
    EBS_SUPPORT = 25  # Energy Based Scan
    P2P_PS_UAPSD = 26
    BCAST_FILTERING = 29
    GO_UAPSD = 30

    @classmethod
    def from_name(cls, name: str) -> "UcodeTlvFlag":
        if name == "BTSTATS" or name == "RESERVED_1":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0da0e5bf1522d75d446f5124e17016628d0a149e
            # and in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d2690c0db7146b12e4fc2d572053c823e512758a
            return cls.NEWSCAN
        if name == "UAPSD":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e8e626ad0ca88cc3278279a43f1cef55badf3e46
            return cls.PM_CMD_SUPPORT
        if name == "P2P_PS":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7303dd7f312f0d07a4bf45c62608d5233b5e8062
            # Added in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=198890258fc0f9e3270ed1c1794b7610dad92ada
            return cls.P2P_PM

        return getattr(cls, name)


@enum.unique
class UcodeTlvType(enum.IntEnum):
    """enum iwl_ucode_tlv_type (prefix IWL_UCODE_TLV_)

    This is the type in Type-Length-Value fields.
    """

    INVALID = 0
    INST = 1
    DATA = 2
    INIT = 3
    INIT_DATA = 4
    BOOT = 5
    PROBE_MAX_LEN = 6
    MEM_DESC = 7  # only used in DVM, was "PAN" previously
    RUNT_EVTLOG_PTR = 8
    RUNT_EVTLOG_SIZE = 9
    RUNT_ERRLOG_PTR = 10
    INIT_EVTLOG_PTR = 11
    INIT_EVTLOG_SIZE = 12
    INIT_ERRLOG_PTR = 13
    ENHANCE_SENS_TBL = 14
    PHY_CALIBRATION_SIZE = 15
    WOWLAN_INST = 16
    WOWLAN_DATA = 17
    FLAGS = 18
    SEC_RT = 19
    SEC_INIT = 20
    SEC_WOWLAN = 21
    DEF_CALIB = 22
    PHY_SKU = 23
    SECURE_SEC_RT = 24
    SECURE_SEC_INIT = 25
    SECURE_SEC_WOWLAN = 26
    NUM_OF_CPU = 27
    CSCHEME = 28
    API_CHANGES_SET = 29
    ENABLED_CAPABILITIES = 30
    N_SCAN_CHANNELS = 31
    PAGING = 32
    # (no type 33)
    SEC_RT_USNIFFER = 34
    SDIO_ADMA_ADDR = 35  # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fb7eba711d2169fbd40bc487c191f360332e8b22  # noqa
    FW_VERSION = 36
    # (no type 37)
    FW_DBG_DEST = 38
    FW_DBG_CONF = 39
    FW_DBG_TRIGGER = 40
    # (no types 41-47)
    CMD_VERSIONS = 48
    # (no type 49)
    FW_GSCAN_CAPA = 50
    FW_MEM_SEG = 51
    IML = 52
    FW_FMAC_API_VERSION = 53
    UMAC_DEBUG_ADDRS = 54
    LMAC_DEBUG_ADDRS = 55
    # (no type 56)
    FW_RECOVERY_INFO = 57
    HW_TYPE = 58
    FW_FMAC_RECOVERY_INFO = 59  # not defined in Linux driver, but found in https://github.com/OpenIntelWireless/itlwm/blob/v2.0.0/itlwm/hal_iwx/if_iwxreg.h  # noqa
    FW_FSEQ_VERSION = 60
    PHY_INTEGRATION_VERSION = 61
    PNVM_VERSION = 62
    PNVM_SKU = 64
    TCM_DEBUG_ADDRS = 65
    SEC_TABLE_ADDR = 66
    D3_KEK_KCK_ADDR = 67
    TLV_CURRENT_PC = 68
    UNKNOWN_69 = 69  # not defined in Linux driver, and found in linux-firmware files added on 2023-11-19

    # IWL_UCODE_TLV_CONST_BASE = 0x100
    FW_NUM_STATIONS = 0x100
    UNKNOWN_101 = 0x101  # not defined in Linux driver, and found in linux-firmware files added on 2022-06-09
    UNKNOWN_102 = 0x102  # not defined in Linux driver, and found in linux-firmware files added on 2022-11-08

    UNKNOWN_444 = 0x444  # not defined in Linux driver, but found in Windows firmware files

    # (old) IWL_UCODE_INI_TLV_GROUP = 0x1000000
    OLD_TYPE_DEBUG_INFO = 0x1000000
    OLD_TYPE_BUFFER_ALLOCATION = 0x1000001
    OLD_TYPE_HCMD = 0x1000002
    OLD_TYPE_REGIONS = 0x1000003
    OLD_TYPE_TRIGGERS = 0x1000004
    # OLD_TYPE_DEBUG_FLOW = 0x1000005

    # IWL_UCODE_TLV_DEBUG_BASE = 0x1000005
    TYPE_DEBUG_INFO = 0x1000005
    TYPE_BUFFER_ALLOCATION = 0x1000006
    TYPE_HCMD = 0x1000007
    TYPE_REGIONS = 0x1000008
    TYPE_TRIGGERS = 0x1000009
    TYPE_CONF_SET = 0x100000A
    UNKNOWN_100000b = 0x100000B
    UNKNOWN_100000c = 0x100000C  # not defined in Linux driver, and found in linux-firmware files added on 2022-11-08

    # TLVs 0x1000-0x2000 are for internal driver usage
    FW_DBG_DUMP_LST = 0x1000

    def __str__(self) -> str:
        return str(self.name)

    @classmethod
    def from_name(cls, name: str) -> "UcodeTlvType":
        if name == "PAN":
            # DVM "PAN" is MVM "MEM_DESC"
            return cls.MEM_DESC

        if name == "OLD_TYPE_DEBUG_FLOW":
            # TYPE_DEBUG_INFO moved on 0x1000005
            return cls.TYPE_DEBUG_INFO

        if name == "TYPE_DEBUG_FLOW":
            # IWL_UCODE_TLV_DEBUG_BASE + 5 was moved to 0x100000A
            return cls.TYPE_CONF_SET

        return getattr(cls, name)


@enum.unique
class OldUcodeType(enum.IntEnum):
    """old enum iwl_ucode_type (prefix IWL_UCODE_)

    Commit https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b5ea1624833b816184aa262c190f2774b8d2ea63  # noqa
    removed IWL_UCODE_NONE from this structure, shifted the values down by one.
    """

    NONE = 0
    REGULAR = 1
    INIT = 2
    WOWLAN = 3


@enum.unique
class UcodeType(enum.IntEnum):
    """enum iwl_ucode_type (prefix IWL_UCODE_)"""

    REGULAR = 0
    INIT = 1
    WOWLAN = 2
    REGULAR_USNIFFER = 3


@enum.unique
class MvmCommandGroups(enum.IntEnum):
    """enum iwl_mvm_command_groups (suffix _GROUP)

    https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/tree/drivers/net/wireless/intel/iwlwifi/fw/api/commands.h
    """

    LEGACY = 0x0
    LONG = 0x1
    SYSTEM = 0x2
    MAC_CONF = 0x3  # Medium Access Controller Configuration
    PHY_OPS = 0x4  # Physical Layer Operations
    DATA_PATH = 0x5
    SCAN = 0x6
    NAN = 0x7  # Neighbor Awareness Networking
    LOCATION = 0x8  # Was TOF (Time of Flight)
    PROT_OFFLOAD = 0xB  # Protocol Offload
    REGULATORY_AND_NVM = 0xC  # Non-Volatile Memory
    DEBUG = 0xF

    @classmethod
    def from_name(cls, name: str) -> "MvmCommandGroups":
        if name.endswith("_GROUP"):
            name = name[:-6]
        if name == "TOF":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3a894a9f319f0b4a36857683c4caacc371a40d25  # noqa
            # and later replaced with LOCATION
            return cls.LOCATION
        return getattr(cls, name)


@enum.unique
class LegacyCmds(enum.IntEnum):
    """enum iwl_legacy_cmds"""

    UCODE_ALIVE_NTFY = 0x01
    REPLY_ERROR = 0x02
    ECHO_CMD = 0x03
    INIT_COMPLETE_NOTIF = 0x04
    PHY_CONTEXT_CMD = 0x08
    DBG_CFG = 0x09
    ANTENNA_COUPLING_NOTIFICATION = 0x0A
    SCAN_CFG_CMD = 0x0C
    SCAN_REQ_UMAC = 0x0D
    SCAN_ABORT_UMAC = 0x0E
    SCAN_COMPLETE_UMAC = 0x0F
    TOF_CMD = 0x10
    TOF_NOTIFICATION = 0x11
    BA_WINDOW_STATUS_NOTIFICATION_ID = 0x13
    ADD_STA_KEY = 0x17
    ADD_STA = 0x18
    REMOVE_STA = 0x19
    FW_GET_ITEM_CMD = 0x1A
    N_3945_RX = 0x1B  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n100
    TX_CMD = 0x1C
    SCD_QUEUE_CFG = 0x1D
    TXPATH_FLUSH = 0x1E
    MGMT_MCAST_KEY = 0x1F
    WEP_KEY = 0x20
    SHARED_MEM_CFG = 0x25
    TDLS_CHANNEL_SWITCH_CMD = 0x27
    MAC_CONTEXT_CMD = 0x28
    TIME_EVENT_CMD = 0x29
    TIME_EVENT_NOTIFICATION = 0x2A
    BINDING_CONTEXT_CMD = 0x2B
    TIME_QUOTA_CMD = 0x2C
    NON_QOS_TX_COUNTER_CMD = 0x2D
    C_RATE_SCALE = 0x47  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n102
    LEDS_CMD = 0x48
    LQ_CMD = 0x4E  # Link Quality
    FW_PAGING_BLOCK_CMD = 0x4F
    SCAN_OFFLOAD_REQUEST_CMD = 0x51
    SCAN_OFFLOAD_ABORT_CMD = 0x52
    HOT_SPOT_CMD = 0x53
    NET_DETECT_CONFIG_CMD = 0x54
    # NET_DETECT_PROFILES_QUERY_CMD = 0x56
    SCAN_OFFLOAD_PROFILES_QUERY_CMD = 0x56
    NET_DETECT_PROFILES_CMD = 0x57
    # NET_DETECT_HOTSPOTS_CMD = 0x58 Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/drivers/net/wireless/iwlwifi/mvm/fw-api.h?id=b04998f3d57adc9ccde264b125bc4ff00b9993d5
    SCAN_OFFLOAD_HOTSPOTS_CONFIG_CMD = 0x58
    # NET_DETECT_HOTSPOTS_QUERY_CMD = 0x59 Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/drivers/net/wireless/iwlwifi/mvm/fw-api.h?id=b04998f3d57adc9ccde264b125bc4ff00b9993d5
    SCAN_OFFLOAD_HOTSPOTS_QUERY_CMD = 0x59
    BT_COEX_UPDATE_SW_BOOST = 0x5A
    BT_COEX_UPDATE_CORUN_LUT = 0x5B
    BT_COEX_UPDATE_REDUCED_TXP = 0x5C
    BT_COEX_CI = 0x5D
    TEMPERATURE_NOTIFICATION = 0x62
    CALIBRATION_CFG_CMD = 0x65
    CALIBRATION_RES_NOTIFICATION = 0x66
    CALIBRATION_COMPLETE_NOTIFICATION = 0x67
    RADIO_VERSION_NOTIFICATION = 0x68
    PHY_CONFIGURATION_CMD = 0x6A
    CALIB_RES_NOTIF_PHY_DB = 0x6B
    PHY_DB_CMD = 0x6C
    SCAN_OFFLOAD_COMPLETE = 0x6D
    SCAN_OFFLOAD_UPDATE_PROFILES_CMD = 0x6E
    SCAN_OFFLOAD_CONFIG_CMD = 0x6F
    C_CHANNEL_SWITCH = 0x72  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n107
    N_CHANNEL_SWITCH = 0x73  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n108
    C_SPECTRUM_MEASUREMENT = 0x74  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n109
    N_SPECTRUM_MEASUREMENT = 0x75  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n110
    POWER_TABLE_CMD = 0x77
    PSM_UAPSD_AP_MISBEHAVING_NOTIFICATION = 0x78
    N_PM_SLEEP = 0x7A  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n114
    N_PM_DEBUG_STATS = 0x7B  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n115
    REPLY_THERMAL_MNG_BACKOFF = 0x7E
    SCAN_REQUEST_CMD = 0x80
    SCAN_ABORT_CMD = 0x81
    SCAN_START_NOTIFICATION = 0x82
    # SCAN_RESULTS_NOTIFICATION = 0x83
    DC2DC_CONFIG_CMD = 0x83
    SCAN_COMPLETE_NOTIFICATION = 0x84
    NVM_ACCESS_CMD = 0x88
    SET_CALIB_DEFAULT_CMD = 0x8E
    BEACON_NOTIFICATION = 0x90
    BEACON_TEMPLATE_CMD = 0x91
    C_TX_PWR_TBL = 0x97  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n129
    TX_ANT_CONFIGURATION_CMD = 0x98
    BT_CONFIG = 0x9B
    STATISTICS_CMD = 0x9C
    STATISTICS_NOTIFICATION = 0x9D
    EOSP_NOTIFICATION = 0x9E
    REDUCE_TX_POWER_CMD = 0x9F
    CARD_STATE_CMD = 0xA0
    CARD_STATE_NOTIFICATION = 0xA1
    MISSED_BEACONS_NOTIFICATION = 0xA2
    C_CT_KILL_CONFIG = 0xA4  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n144
    TDLS_CONFIG_CMD = 0xA7
    C_SENSITIVITY = 0xA8  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n145
    MAC_PM_POWER_TABLE = 0xA9
    TDLS_CHANNEL_SWITCH_NOTIFICATION = 0xAA
    C_PHY_CALIBRATION = 0xB0  # From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/wireless/intel/iwlegacy/commands.h?h=v5.16#n146
    MFUART_LOAD_NOTIFICATION = 0xB1
    RSS_CONFIG_CMD = 0xB3
    SCAN_ITERATION_COMPLETE_UMAC = 0xB5
    REPLY_RX_PHY_CMD = 0xC0
    REPLY_RX_MPDU_CMD = 0xC1
    BAR_FRAME_RELEASE = 0xC2
    FRAME_RELEASE = 0xC3
    BA_NOTIF = 0xC5
    MCC_UPDATE_CMD = 0xC8
    MCC_CHUB_UPDATE_CMD = 0xC9
    MARKER_CMD = 0xCB
    BT_COEX_PRIO_TABLE = 0xCC
    BT_COEX_PROT_ENV = 0xCD
    BT_PROFILE_NOTIFICATION = 0xCE
    BCAST_FILTER_CMD = 0xCF
    MCAST_FILTER_CMD = 0xD0
    REPLY_SF_CFG_CMD = 0xD1
    REPLY_BEACON_FILTERING_CMD = 0xD2
    D3_CONFIG_CMD = 0xD3
    PROT_OFFLOAD_CONFIG_CMD = 0xD4
    OFFLOADS_QUERY_CMD = 0xD5
    REMOTE_WAKE_CONFIG_CMD = 0xD6
    MATCH_FOUND_NOTIFICATION = 0xD9
    CMD_DTS_MEASUREMENT_TRIGGER = 0xDC
    DTS_MEASUREMENT_NOTIFICATION = 0xDD
    WOWLAN_PATTERNS = 0xE0
    WOWLAN_CONFIGURATION = 0xE1
    WOWLAN_TSC_RSC_PARAM = 0xE2
    WOWLAN_TKIP_PARAM = 0xE3
    WOWLAN_KEK_KCK_MATERIAL = 0xE4
    WOWLAN_GET_STATUSES = 0xE5
    WOWLAN_TX_POWER_PER_DB = 0xE6
    SCAN_ITERATION_COMPLETE = 0xE7
    D0I3_END_CMD = 0xED
    LTR_CONFIG = 0xEE
    REPLY_DEBUG_CMD = 0xF0
    LDBG_CONFIG_CMD = 0xF6
    DEBUG_LOG_MSG = 0xF7

    @classmethod
    def from_name(cls, name: str) -> "LegacyCmds":
        if name == "MVM_ALIVE":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9422b978355e569c2791b67f78274668102eb750  # noqa
            return cls.UCODE_ALIVE_NTFY
        if name == "SCAN_RESULTS_NOTIFICATION":
            # SCAN_RESULTS_NOTIFICATION was removed, then DC2DC_CONFIG_CMD was created with the same ID (0x83)
            return cls.DC2DC_CONFIG_CMD

        # NET_DETECT_... were renamed SCAN_OFFLOAD_...
        if name == "NET_DETECT_PROFILES_QUERY_CMD":
            return cls.SCAN_OFFLOAD_PROFILES_QUERY_CMD
        if name == "NET_DETECT_HOTSPOTS_CMD":
            return cls.SCAN_OFFLOAD_HOTSPOTS_CONFIG_CMD
        if name == "NET_DETECT_HOTSPOTS_QUERY_CMD":
            return cls.SCAN_OFFLOAD_HOTSPOTS_QUERY_CMD

        return getattr(cls, name)


@enum.unique
class SystemSubcmdIds(enum.IntEnum):
    """enum iwl_system_subcmd_ids"""

    SHARED_MEM_CFG_CMD = 0x00
    SOC_CONFIGURATION_CMD = 0x01
    INIT_EXTENDED_CFG_CMD = 0x03
    FW_ERROR_RECOVERY_CMD = 0x07
    RFI_CONFIG_CMD = 0x0B
    RFI_GET_FREQ_TABLE_CMD = 0x0C
    SYSTEM_FEATURES_CONTROL_CMD = 0x0D
    RFI_DEACTIVATE_NOTIF = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "SystemSubcmdIds":
        if name == "FSEQ_VER_MISMATCH_NTF":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=07fb3299adc40b2e87bbe7047b7b1614deae0d05  # noqa
            # and later replaced with RFI_DEACTIVATE_NOTIF in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=63b62a2df04135ca1da7c735ac18fc34cd87bbfb  # noqa
            return cls.RFI_DEACTIVATE_NOTIF
        return getattr(cls, name)


@enum.unique
class MacConfSubcmdIds(enum.IntEnum):
    """enum iwl_mac_conf_subcmd_ids"""

    LINK_QUALITY_MEASUREMENT_CMD = 0x01
    LOW_LATENCY_CMD = 0x03
    CHANNEL_SWITCH_TIME_EVENT_CMD = 0x04
    SESSION_PROTECTION_CMD = 0x05
    CANCEL_CHANNEL_SWITCH_CMD = 0x06
    CHANNEL_SWITCH_ERROR_NOTIF = 0xF9
    MISSED_VAP_NOTIF = 0xFA
    SESSION_PROTECTION_NOTIF = 0xFB
    PROBE_RESPONSE_DATA_NOTIF = 0xFC
    LINK_QUALITY_MEASUREMENT_COMPLETE_NOTIF = 0xFE
    CHANNEL_SWITCH_START_NOTIF = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "MacConfSubcmdIds":
        if name == "CHANNEL_SWITCH_NOA_NOTIF":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6905eb1c3b9ee4580f5d2c7fd9f2bbcc74ec26eb  # noqa
            return cls.CHANNEL_SWITCH_START_NOTIF
        return getattr(cls, name)


@enum.unique
class PhyOpsSubcmdIds(enum.IntEnum):
    """enum iwl_phy_ops_subcmd_ids"""

    CMD_DTS_MEASUREMENT_TRIGGER_WIDE = 0x00
    CTDP_CONFIG_CMD = 0x03
    TEMP_REPORTING_THRESHOLDS_CMD = 0x04
    PER_CHAIN_LIMIT_OFFSET_CMD = 0x05
    PER_PLATFORM_ANT_GAIN_CMD = 0x07
    CT_KILL_NOTIFICATION = 0xFE
    DTS_MEASUREMENT_NOTIF_WIDE = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "PhyOpsSubcmdIds":
        if name == "GEO_TX_POWER_LIMIT":
            # Renamed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=523de6c872ca89e2a636f5c03ab48fc0769e132b  # noqa
            return cls.PER_CHAIN_LIMIT_OFFSET_CMD
        return getattr(cls, name)


@enum.unique
class DataPathSubcmdIds(enum.IntEnum):
    """enum iwl_data_path_subcmd_ids"""

    DQA_ENABLE_CMD = 0x00
    UPDATE_MU_GROUPS_CMD = 0x01
    TRIGGER_RX_QUEUES_NOTIF_CMD = 0x02
    STA_HE_CTXT_CMD = 0x07
    RLC_CONFIG_CMD = 0x08
    RFH_QUEUE_CONFIG_CMD = 0x0D
    TLC_MNG_CONFIG_CMD = 0x0F
    TLC_MNG_NOTIF_REQ_CMD = 0x10
    HE_AIR_SNIFFER_CONFIG_CMD = 0x13
    CHEST_COLLECTOR_FILTER_CONFIG_CMD = 0x14
    RX_BAID_ALLOCATION_CONFIG_CMD = 0x16
    SCD_QUEUE_CONFIG_CMD = 0x17
    SEC_KEY_CMD = 0x18
    MONITOR_NOTIF = 0xF4
    RX_NO_DATA_NOTIF = 0xF5
    THERMAL_DUAL_CHAIN_REQUEST = 0xF6
    TLC_MNG_UPDATE_NOTIF = 0xF7
    STA_PM_NOTIF = 0xFD
    MU_GROUP_MGMT_NOTIF = 0xFE
    RX_QUEUES_NOTIFICATION = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "DataPathSubcmdIds":
        if name == "TLC_MNG_AMSDU_ENABLE_NOTIF":
            # Removed in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2c2b4bbc5d1f5c37e16d108f7a0c4e2a36c4f423  # noqa
            return cls.THERMAL_DUAL_CHAIN_REQUEST
        return getattr(cls, name)


@enum.unique
class ScanSubcmdIds(enum.IntEnum):
    """enum iwl_scan_subcmd_ids"""

    OFFLOAD_MATCH_INFO_NOTIF = 0xFC

    @classmethod
    def from_name(cls, name: str) -> "ScanSubcmdIds":
        return getattr(cls, name)


@enum.unique
class NanSubcmdIds(enum.IntEnum):
    """enum iwl_nan_subcmd_ids (Neighbor Awareness Networking)"""

    NAN_CONFIG_CMD = 0x00
    NAN_DISCOVERY_FUNC_CMD = 0x01
    NAN_FAW_CONFIG_CMD = 0x02
    NAN_DISCOVERY_EVENT_NOTIF = 0xFD
    NAN_DISCOVERY_TERMINATE_NOTIF = 0xFE
    NAN_FAW_START_NOTIF = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "NanSubcmdIds":
        return getattr(cls, name)


@enum.unique
class LocationSubcmdIds(enum.IntEnum):
    """enum iwl_location_subcmd_ids"""

    TOF_RANGE_REQ_CMD = 0x00
    TOF_CONFIG_CMD = 0x01
    TOF_RANGE_ABORT_CMD = 0x02
    TOF_RANGE_REQ_EXT_CMD = 0x03
    TOF_RESPONDER_CONFIG_CMD = 0x04
    TOF_RESPONDER_DYN_CONFIG_CMD = 0x05
    CSI_HEADER_NOTIFICATION = 0xFA
    CSI_CHUNKS_NOTIFICATION = 0xFB
    TOF_LC_NOTIF = 0xFC
    TOF_RESPONDER_STATS = 0xFD
    TOF_MCSI_DEBUG_NOTIF = 0xFE
    TOF_RANGE_RESPONSE_NOTIF = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "LocationSubcmdIds":
        return getattr(cls, name)


@enum.unique
class ProtOffloadSubcmdIds(enum.IntEnum):
    """enum iwl_prot_offload_subcmd_ids (Protocol Offload)"""

    WOWLAN_WAKE_PKT_NOTIFICATION = 0xFC
    WOWLAN_INFO_NOTIFICATION = 0xFD
    D3_END_NOTIFICATION = 0xFE
    STORED_BEACON_NTF = 0xFF

    @classmethod
    def from_name(cls, name: str) -> "ProtOffloadSubcmdIds":
        return getattr(cls, name)


@enum.unique
class RegulatoryAndNvmSubcmdIds(enum.IntEnum):
    """enum iwl_regulatory_and_nvm_subcmd_ids (Regulatory and Non-Volatile Memory)"""

    NVM_ACCESS_COMPLETE = 0x00
    LARI_CONFIG_CHANGE = 0x01
    NVM_GET_INFO = 0x02
    TAS_CONFIG = 0x03
    SAR_OFFSET_MAPPING_TABLE_CMD = 0x04
    PNVM_INIT_COMPLETE_NTFY = 0xFE

    @classmethod
    def from_name(cls, name: str) -> "RegulatoryAndNvmSubcmdIds":
        return getattr(cls, name)


@enum.unique
class DebugCmds(enum.IntEnum):
    """enum iwl_debug_cmds"""

    LMAC_RD_WR = 0x00
    UMAC_RD_WR = 0x01
    HOST_EVENT_CFG = 0x03
    DBGC_SUSPEND_RESUME = 0x07
    BUFFER_ALLOCATION = 0x08
    FW_DUMP_COMPLETE_CMD = 0x0B
    MFU_ASSERT_DUMP_NTF = 0xFE

    @classmethod
    def from_name(cls, name: str) -> "DebugCmds":
        return getattr(cls, name)


GROUP_CMD_ENUM: Mapping[int, Type[enum.IntEnum]] = {
    MvmCommandGroups.LEGACY.value: LegacyCmds,
    MvmCommandGroups.LONG.value: LegacyCmds,  # Legacy commands uses a LONG header and the same table as LEGACY
    MvmCommandGroups.SYSTEM.value: SystemSubcmdIds,
    MvmCommandGroups.MAC_CONF.value: MacConfSubcmdIds,
    MvmCommandGroups.PHY_OPS.value: PhyOpsSubcmdIds,
    MvmCommandGroups.DATA_PATH.value: DataPathSubcmdIds,
    MvmCommandGroups.SCAN.value: ScanSubcmdIds,
    MvmCommandGroups.NAN.value: NanSubcmdIds,
    MvmCommandGroups.LOCATION.value: LocationSubcmdIds,
    MvmCommandGroups.PROT_OFFLOAD.value: ProtOffloadSubcmdIds,
    MvmCommandGroups.REGULATORY_AND_NVM.value: RegulatoryAndNvmSubcmdIds,
    MvmCommandGroups.DEBUG.value: DebugCmds,
}


# struct iwl_ucode_header, version 1
UcodeHeaderV1 = Struct(
    "version_serial" / Int8ul,
    "version_api" / Int8ul,  # 0, 1 and 2
    "version_minor" / Int8ul,
    "version_major" / Int8ul,
    "inst_size" / Hex(Int32ul),  # bytes of runtime code
    "data_size" / Hex(Int32ul),  # bytes of runtime data
    "init_size" / Hex(Int32ul),  # bytes of init code
    "init_data_size" / Hex(Int32ul),  # bytes of init data
    "boot_size" / Hex(Int32ul),  # bytes of bootstrap code
)
assert UcodeHeaderV1.sizeof() == 0x18

# struct iwl_ucode_header, version 2
UcodeHeaderV2 = Struct(
    "version_serial" / Int8ul,
    "version_api" / Int8ul,  # 3 or more
    "version_minor" / Int8ul,
    "version_major" / Int8ul,
    "build" / Hex(Int32ul),  # build number
    "inst_size" / Hex(Int32ul),  # bytes of runtime code
    "data_size" / Hex(Int32ul),  # bytes of runtime data
    "init_size" / Hex(Int32ul),  # bytes of init code
    "init_data_size" / Hex(Int32ul),  # bytes of init data
    "boot_size" / Hex(Int32ul),  # bytes of bootstrap code
)
assert UcodeHeaderV2.sizeof() == 0x1C

# struct iwl_tlv_ucode_header
TlvUcodeHeader = Struct(
    "_zero" / Const(0, Int32ul),
    "_magic" / Const(0x0A4C5749, Int32ul),  # IWL_TLV_UCODE_MAGIC = 0x0a4c5749 "IWL\n"
    "human_readable" / PaddedString(0x40, "ascii"),
    "version" / Int32ul,
    "build" / Hex(Int32ul),
    "ignore" / Int64ul,
)
assert TlvUcodeHeader.sizeof() == 0x58

# struct iwl_ucode_tlv
UcodeTlv = Struct(
    "type_" / Enum(Int32ul, UcodeTlvType),
    "length" / Rebuild(Int32ul, len_(this.data)),
    "data" / Bytes(this.length),
)

# struct iwl_fw_cipher_scheme
CipherScheme = Struct(
    "cipher" / Hex(Int32ul),
    "flags" / Hex(Int8ul),
    "hdr_len" / Int8ul,
    "pn_len" / Int8ul,
    "pn_off" / Int8ul,
    "key_idx_off" / Int8ul,
    "key_idx_mask" / Int8ul,
    "key_idx_shift" / Int8ul,
    "mic_len" / Int8ul,
    "hw_cipher" / Hex(Int8ul),
)
assert CipherScheme.sizeof() == 0xD

# struct iwl_fw_cmd_version
CmdVersion = Struct(
    "cmd" / Hex(Int8ul),
    "group" / Hex(Int8ul),
    "cmd_ver" / Int8ul,
    "notif_ver" / Int8ul,
)
assert CmdVersion.sizeof() == 4

# struct iwl_fw_dbg_conf_hcmd
FwDbgConfHcmd = Struct(
    "id" / Enum(Int8ul, LegacyCmds),
    "_reserved" / Const(0, Int8ul),
    "len" / Rebuild(Int16ul, len_(this.data)),
    "data" / Bytes(this.len),
)

# struct iwl_fw_dbg_conf_tlv
FwDbgConfTlv = Struct(
    "id" / Int8ul,
    "usniffer" / Int8ul,
    "_reserved" / Const(0, Int8ul),
    "num_of_hcmds" / Int8ul,
    "hcmd" / GreedyRange(FwDbgConfHcmd),
)

# struct iwl_fw_dbg_reg_op
FwDbgRegOp = Struct(
    "op" / Enum(Int32ul, FwDbgRegOperator),
    "addr" / Hex(Int32ul),
    "val" / Hex(Int32ul),
)
assert FwDbgRegOp.sizeof() == 0xC

# struct iwl_fw_dbg_dest_tlv_v1
FwDbgDestTlvV1 = Struct(
    "version" / Const(0, Int8ul),
    "monitor_mode" / Int8ul,
    "size_power" / Int8ul,
    "_reserved" / Const(0, Int8ul),
    "base_reg" / Hex(Int32ul),
    "end_reg" / Hex(Int32ul),
    "write_ptr_reg" / Hex(Int32ul),
    "wrap_count" / Hex(Int32ul),
    "base_shift" / Int8ul,
    "end_shift" / Int8ul,
    "reg_ops" / GreedyRange(FwDbgRegOp),
)

# struct iwl_fw_dbg_dest_tlv
FwDbgDestTlv = Struct(
    "version" / Const(1, Int8ul),
    "monitor_mode" / Int8ul,
    "size_power" / Int8ul,
    "_reserved" / Const(0, Int8ul),
    "cfg_reg" / Hex(Int32ul),
    "write_ptr_reg" / Hex(Int32ul),
    "wrap_count" / Hex(Int32ul),
    "base_shift" / Int8ul,
    "end_shift" / Int8ul,
    "reg_ops" / GreedyRange(FwDbgRegOp),
)

# struct iwl_fw_dbg_mem_seg_tlv
FwDbgMemSegTlv = Struct(
    "data_type" / Hex(Int32ul),
    "ofs" / Hex(Int32ul),
    "len" / Hex(Int32ul),
)
assert FwDbgMemSegTlv.sizeof() == 0xC

# struct iwl_fw_dump_exclude
FwDumpExclude = Struct(
    "addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
)
assert FwDumpExclude.sizeof() == 8

# struct iwl_fw_gscan_capabilities, old format
FwGscanCapabilitiesOld = Struct(
    "max_scan_cache_size" / Int32ul,
    "max_scan_buckets" / Int32ul,
    "max_ap_cache_per_scan" / Int32ul,
    "max_rssi_sample_size" / Int32ul,
    "max_scan_reporting_threshold" / Int32ul,
    "max_hotlist_aps" / Int32ul,
    "max_significant_change_aps" / Int32ul,
    "max_bssid_history_entries" / Int32ul,
)
assert FwGscanCapabilitiesOld.sizeof() == 0x20

# struct iwl_fw_gscan_capabilities, new format
FwGscanCapabilities = Struct(
    "max_scan_cache_size" / Int32ul,
    "max_scan_buckets" / Int32ul,
    "max_ap_cache_per_scan" / Int32ul,
    "max_rssi_sample_size" / Int32ul,
    "max_scan_reporting_threshold" / Int32ul,
    "max_hotlist_aps" / Int32ul,
    "max_significant_change_aps" / Int32ul,
    "max_bssid_history_entries" / Int32ul,
    "max_hotlist_ssids" / Int32ul,
    "max_number_epno_networks" / Int32ul,
    "max_number_epno_networks_by_ssid" / Int32ul,
    "max_number_of_white_listed_ssid" / Int32ul,
    "max_number_of_black_listed_ssid" / Int32ul,
)
assert FwGscanCapabilities.sizeof() == 0x34

# struct iwl_fw_ini_allocation_tlv
FwIniAllocationTlv = Struct(
    "_version" / Const(1, Int32ul),
    "domain" / Enum(Int32ul, FwIniDbgDomain),
    "alloc_id" / Enum(Int32ul, FwIniAllocationId),
    "buf_location" / Enum(Int32ul, FwIniBufferLocation),
    "req_size" / Hex(Int32ul),
    "max_frags_num" / Int32ul,
    "min_size" / Hex(Int32ul),
)
assert FwIniAllocationTlv.sizeof() == 0x1C

# struct iwl_fw_ini_debug_info_tlv
FwIniDebugInfoTlv = Struct(
    "_version" / Const(1, Int32ul),
    "domain" / Enum(Int32ul, FwIniDbgDomain),
    "image_type" / Int32ul,
    "debug_cfg_name" / PaddedString(0x40, "ascii"),
)
assert FwIniDebugInfoTlv.sizeof() == 0x4C

# struct iwl_fw_ini_hcmd_tlv
FwInitHcmdTlv = Struct(
    "_version" / Const(1, Int32ul),
    "domain" / Enum(Int32ul, FwIniDbgDomain),
    "time_point" / Int32ul,
    "period_msec" / Int32ul,
    "hcmd_id" / Hex(Int8ul),
    "hcmd_group" / Hex(Int8ul),
    "_reserved" / Const(0, Int16ul),
    "data" / GreedyBytes,
)

# struct iwl_fw_ini_region_tlv
FwIniRegionTlv = Struct(
    "version" / Int32ul,  # 1 or 2
    "domain" / Enum(Int32ul, FwIniDbgDomain),
    "id_" / Int32ul,
    "type_" / Enum(Int8ul, FwIniRegionType),
    "sub_type" / Int8ul,
    "sub_type_ver" / Int8ul,
    "_reserved" / Const(0, Int8ul),
    "name" / PaddedString(0x20, "ascii"),
    "regconf_union" / Bytes(0x10),
    "addr" / GreedyRange(Hex(Int32ul)),
)

# struct iwl_fw_ini_region_dev_addr
FwIniRegionDevAddr = Struct(
    "size" / Hex(Int32ul),
    "offset" / Hex(Int32ul),
    "_padding1" / Const(0, Int32ul),
    "_padding2" / Const(0, Int32ul),
)
assert FwIniRegionDevAddr.sizeof() == 0x10

# struct iwl_fw_ini_region_err_table
FwIniRegionErrTable = Struct(
    "version" / Int32ul,
    "base_addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
    "offset" / Hex(Int32ul),
)
assert FwIniRegionErrTable.sizeof() == 0x10

# struct iwl_fw_ini_region_fifos
FwIniRegionFifos = Struct(
    "fid0" / Hex(Int32ul),
    "fid1" / Hex(Int32ul),
    "hdr_only" / Int32ul,
    "offset" / Hex(Int32ul),
)
assert FwIniRegionFifos.sizeof() == 0x10

# struct iwl_fw_ini_region_internal_buffer
FwIniRegionInternalBuffer = Struct(
    "alloc_id" / Int32ul,
    "base_addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
    "_padding1" / Const(0, Int32ul),
)
assert FwIniRegionInternalBuffer.sizeof() == 0x10

# struct iwl_fw_ini_region_special_device_memory
FwIniRegionSpecialDeviceMemory = Struct(
    "type_" / Int16ul,
    "version" / Int16ul,
    "base_addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
    "offset" / Hex(Int32ul),
)
assert FwIniRegionSpecialDeviceMemory.sizeof() == 0x10

# struct iwl_fw_ini_trigger_tlv
FwInitTriggerTlv = Struct(
    "_version" / Const(1, Int32ul),
    "domain" / Enum(Int32ul, FwIniDbgDomain),
    "time_point" / Int32ul,
    "trigger_reason" / Hex(Int32ul),
    "apply_policy" / Hex(Int32ul),
    "dump_delay" / Int32ul,
    "occurrences" / Int32ul,
    "reserved" / Hex(Int32ul),
    "ignore_consec" / Int32ul,
    "reset_fw" / Int32ul,
    "multi_dut" / Int32ul,
    "regions_mask" / Hex(Int64ul),
    "data" / GreedyBytes,
)

# Data of FW_RECOVERY_INFO entries
FwRecoveryInfo = Struct(
    "addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
)
assert FwRecoveryInfo.sizeof() == 8

# Data of FW_VERSION entries
FwVersion = Struct(
    "major" / Int32ul,
    "minor" / Int32ul,
    "local_comp" / Int32ul,
)
assert FwVersion.sizeof() == 0xC

# Data of HW_TYPE entries
HwType = Struct(
    "mac_type" / Hex(Int16ul),
    "rf_type" / Hex(Int16ul),
    "_padding" / Bytes(8),
)
assert HwType.sizeof() == 0xC

# struct iwl_lmac_debug_addrs
LmacDebugAddrs = Struct(
    "error_event_table_ptr" / Hex(Int32ul),  # SRAM address for error log
    "log_event_table_ptr" / Hex(Int32ul),  # SRAM address for LMAC event log
    "cpu_register_ptr" / Hex(Int32ul),
    "dbgm_config_ptr" / Hex(Int32ul),
    "alive_counter_ptr" / Hex(Int32ul),
    "scd_base_ptr" / Hex(Int32ul),  # SRAM address for SCD
    "st_fwrd_addr" / Hex(Int32ul),  # pointer to Store and forward
    "st_fwrd_size" / Hex(Int32ul),
)
assert LmacDebugAddrs.sizeof() == 0x20

# Data of MEM_DESC entries
MemDesc = Struct(
    "addr" / Hex(Int32ul),
    "len" / Rebuild(Int32ul, len_(this.data)),
    "data" / Bytes(this.len),
)

# Data of SEC_RT, SEC_INIT... entries
SecData = Struct(
    "addr" / Hex(Int32ul),
    "data" / Hex(GreedyBytes),
)

# struct iwl_sku_id
SkuId = Struct(
    "data" / Array(3, Hex(Int32ul)),
)
assert SkuId.sizeof() == 0xC

# struct iwl_umac_debug_addrs
UmacDebugAddrs = Struct(
    "error_info_addr" / Hex(Int32ul),
    "dbg_print_buff_addr" / Hex(Int32ul),
)
assert UmacDebugAddrs.sizeof() == 8

# struct iwl_ucode_api
UcodeApi = Struct(
    "api_index" / Int32ul,
    "api_flags" / Hex(Int32ul),
)
assert UcodeApi.sizeof() == 8

# struct iwl_ucode_capa
UcodeCapa = Struct(
    "api_index" / Int32ul,
    "api_capa" / Hex(Int32ul),
)
assert UcodeCapa.sizeof() == 8

# struct iwl_tlv_calib_data and struct iwl_tlv_calib_ctrl
TlvCalibData = Struct(
    "ucode_type" / Enum(Int32ul, UcodeType),
    "flow_trigger" / Hex(Int32ul),
    "event_trigger" / Hex(Int32ul),
)
assert TlvCalibData.sizeof() == 0xC

# "CSS", section with signature information. The header looks like ACM
# (Authenticated Code Modules) used by Intel TXT
CodeSignatureSectionInfo = Struct(
    "flags" / Hex(Int32ul),
    "size_plus_8" / Hex(Int32ul),
    "addr" / Hex(Int32ul),
    "size" / Hex(Int32ul),
)
# CSS signed using RSA 2048 and SHA256
CodeSignatureSectionRsa2048 = Struct(
    "module_type" / Const(6, Int16ul),
    "module_subtype" / Const(0, Int16ul),
    "header_size" / Const(0xA1, Int32ul),  # Header size in 32-bit words (0x284 bytes)
    "header_version_major" / Const(0, Int16ul),
    "header_version_minor" / Const(1, Int16ul),
    "module_id" / Const(0, Int16ul),
    "flags" / Hex(Int16ul),
    "module_vendor" / Const(0x8086, Hex(Int32ul)),
    "date" / Hex(Int32ul),
    "size" / Hex(Int32ul),
    "unknown_0x1c" / Hex(Int32ul),
    "unknown_0x20" / Hex(Int32ul),
    "unknown_0x24" / Hex(Int32ul),
    "unknown_0x28" / Hex(Int32ul),
    "unknown_0x2c" / Hex(Int32ul),
    "unknown_0x30" / Hex(Int32ul),
    "reserved" / Bytes(0x4C),
    "rsa_modulus" / Bytes(0x100),
    "rsa_pubexp" / Int32ul,
    "rsa_signature" / Bytes(0x100),
    "num_sections" / Rebuild(Int32ul, len_(this.sections)),
    "sections" / CodeSignatureSectionInfo[this.num_sections],
)
# CSS signed using secp384r1 Elliptic Curve and SHA384
CodeSignatureSectionEcSecp384r1 = Struct(
    "module_type" / Const(6, Int16ul),
    "module_subtype" / Const(0, Int16ul),
    "header_size" / Const(0x50, Int32ul),  # Header size in 32-bit words (0x140 bytes)
    "header_version_major" / Const(0, Int16ul),
    "header_version_minor" / Const(2, Int16ul),
    "module_id" / Const(0, Int16ul),
    "flags" / Hex(Int16ul),
    "module_vendor" / Const(0x8086, Hex(Int32ul)),
    "date" / Hex(Int32ul),
    "size" / Hex(Int32ul),
    "unknown_0x1c" / Hex(Int32ul),
    "unknown_0x20" / Hex(Int32ul),
    "unknown_0x24" / Hex(Int32ul),
    "unknown_0x28" / Hex(Int32ul),
    "unknown_0x2c" / Hex(Int32ul),
    "unknown_0x30" / Hex(Int32ul),
    "unknown_0x34" / Hex(Int32ul),
    "unknown_0x38" / Hex(Int32ul),
    "reserved" / Bytes(0x44),
    "ec_pub_x" / Bytes(0x30),
    "ec_pub_y" / Bytes(0x30),
    "ec_signature_r" / Bytes(0x30),
    "ec_signature_s" / Bytes(0x30),
    "padding" / Bytes(0x144),
    "num_sections" / Rebuild(Int32ul, len_(this.sections)),
    "sections" / CodeSignatureSectionInfo[this.num_sections],
)

# PKCS#1 v1.5 padding for RSA-SHA256 sinatures
PKCS1_SHA256_PREFIX = bytes.fromhex(
    """
0001ffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffffffffffff
ffffffffffffffffffffffff00303130
0d060960864801650304020105000420
""".replace(
        "\n", ""
    )
)

# secp384r1 (NIST P-384) parameters
SECP384R1_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
SECP384R1_A = -3
SECP384R1_B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF


class EmptyStreamError(Exception):
    pass


class IntelWifiFirmware:
    """Represent an Intel Wi-Fi firmware that can be used by Linux or Windows driver"""

    def __init__(
        self, entries: List[Container], header_type: Optional[str] = None, header: Optional[Container] = None
    ) -> None:
        self.entries = entries
        self.header_type = header_type
        self.header = header

    @classmethod
    def parse_stream(cls, stream: BinaryIO) -> "IntelWifiFirmware":
        """Parse a firmware from a stream"""
        # Match a header
        header_type: Optional[str] = None
        header: Optional[Container] = None
        peeked_data = stream.read(16)
        if peeked_data == b"":
            # End of file
            raise EmptyStreamError()
        elif peeked_data.startswith(b"\0\0\0\0IWL\n"):
            # Intel Wireless Linux magic, parse a header
            stream.seek(-len(peeked_data), io.SEEK_CUR)
            header = TlvUcodeHeader.parse_stream(stream)
            header_type = "TlvUcodeHeader"
        elif peeked_data == b"*WESTOPFORNOONE*":
            # Windows .dat file, skip the marker
            pass
        elif peeked_data[2:4] == b"\0\0":
            # Some firmware directly starts with TLV entries
            stream.seek(-len(peeked_data), io.SEEK_CUR)
        elif peeked_data[1] in {0, 1, 2}:
            # Old firmware in v1 format (before TLV)
            stream.seek(-len(peeked_data), io.SEEK_CUR)
            header = UcodeHeaderV1.parse_stream(stream)
            rt_code = Bytes(header.inst_size).parse_stream(stream)
            rt_data = Bytes(header.data_size).parse_stream(stream)
            init_code = Bytes(header.init_size).parse_stream(stream)
            init_data = Bytes(header.init_data_size).parse_stream(stream)
            boot_code = Bytes(header.boot_size).parse_stream(stream)
            entries = [
                Container({"type_": UcodeTlvType.INST, "data": rt_code}),
                Container({"type_": UcodeTlvType.DATA, "data": rt_data}),
                Container({"type_": UcodeTlvType.INIT, "data": init_code}),
                Container({"type_": UcodeTlvType.INIT_DATA, "data": init_data}),
            ]
            if header.boot_size != 0:
                entries.append(Container({"type_": UcodeTlvType.BOOT, "data": boot_code}))
            return cls(entries, header_type="UcodeHeaderV1", header=header)
        else:
            # Old firmware in v1 format (before TLV)
            stream.seek(-len(peeked_data), io.SEEK_CUR)
            header = UcodeHeaderV2.parse_stream(stream)
            rt_code = Bytes(header.inst_size).parse_stream(stream)
            rt_data = Bytes(header.data_size).parse_stream(stream)
            init_code = Bytes(header.init_size).parse_stream(stream)
            init_data = Bytes(header.init_data_size).parse_stream(stream)
            entries = [
                Container({"type_": UcodeTlvType.INST, "data": rt_code}),
                Container({"type_": UcodeTlvType.DATA, "data": rt_data}),
                Container({"type_": UcodeTlvType.INIT, "data": init_code}),
                Container({"type_": UcodeTlvType.INIT_DATA, "data": init_data}),
            ]
            if header.boot_size != 0:
                boot_code = Bytes(header.boot_size).parse_stream(stream)
                entries.append(Container({"type_": UcodeTlvType.BOOT, "data": boot_code}))
            return cls(entries, header_type="UcodeHeaderV2", header=header)

        # Parse TLV entries
        entries = []
        while True:
            peeked_data = stream.read(16)
            if peeked_data == b"":
                # Reached end of file
                break
            stream.seek(-len(peeked_data), io.SEEK_CUR)
            if peeked_data == b"*WESTOPFORNOONE*":
                # Windows firmware separator, stop the parsing here
                break

            entry = UcodeTlv.parse_stream(stream)
            entries.append(entry)

        return cls(entries, header_type=header_type, header=header)

    @classmethod
    def parse_all_stream(cls, stream: BinaryIO) -> Generator["IntelWifiFirmware", None, None]:
        """Parse multiple firmware from a stream"""
        while True:
            try:
                yield cls.parse_stream(stream)
            except EmptyStreamError:
                break

    @classmethod
    def parse_all_bytes(cls, data: bytes) -> Generator["IntelWifiFirmware", None, None]:
        """Parse multiple firmware from bytes"""
        with io.BytesIO(data) as stream:
            yield from cls.parse_all_stream(stream)

    @classmethod
    def parse_all_file(cls, path: Path) -> Generator["IntelWifiFirmware", None, None]:
        """Parse multiple firmware from a file"""
        with path.open("rb") as stream:
            yield from cls.parse_all_stream(stream)

    def write_stream(self, stream: BinaryIO) -> None:
        """Write the firmware to an output stream"""
        if self.header_type is None:
            pass
        elif self.header_type == "UcodeHeaderV1":
            UcodeHeaderV1.build_stream(self.header, stream)
            # The contents of the entries are directly written as-is
            for entry in self.entries:
                stream.write(entry.data)
            return
        elif self.header_type == "UcodeHeaderV2":
            UcodeHeaderV2.build_stream(self.header, stream)
            for entry in self.entries:
                stream.write(entry.data)
            return
        elif self.header_type == "TlvUcodeHeader":
            TlvUcodeHeader.build_stream(self.header, stream)
        else:
            raise NotImplementedError(f"Unsupported FW header {self.header_type!r} ({self.header!r})")

        for entry in self.entries:
            UcodeTlv.build_stream(entry, stream)

    def write_bytes(self) -> bytes:
        """Serialize the firmware to bytes"""
        buffer = io.BytesIO()
        self.write_stream(buffer)
        return buffer.getbuffer()

    def get_entries_by_type(self, entry_type: Union[int, UcodeTlvType]) -> Generator[Any, None, None]:
        """Iterate all entries of the specified type"""
        for entry in self.entries:
            if int(entry.type_) == entry_type:
                current_type, decoded_entry = self.decode_entry(entry)
                assert current_type == entry_type
                yield decoded_entry

    def print_description(self, out: Optional[TextIO] = None) -> None:
        """Print a description of this firmware"""
        self.print_header(out=out)
        for entry in self.entries:
            self.print_entry(entry, out=out)
        print("", file=out)
        self.print_signatures(out=out)

    def print_header(self, out: Optional[TextIO] = None) -> None:
        """Print the header"""
        if self.header_type is None:
            return
        if self.header_type == "UcodeHeaderV1":
            assert self.header is not None
            print(
                f"Header: version {self.header.version_major}.{self.header.version_minor}.{self.header.version_api}.{self.header.version_serial} runtime {self.header.inst_size}+{self.header.data_size} bytes, init {self.header.init_size}+{self.header.init_data_size} bytes, bootstrap {self.header.boot_size} bytes",  # noqa
                file=out,
            )
            return
        if self.header_type == "UcodeHeaderV2":
            assert self.header is not None
            print(
                f"Header: version {self.header.version_major}.{self.header.version_minor}.{self.header.version_api}.{self.header.version_serial} build {self.header.build} runtime {self.header.inst_size}+{self.header.data_size} bytes, init {self.header.init_size}+{self.header.init_data_size} bytes, bootstrap {self.header.boot_size} bytes",  # noqa
                file=out,
            )
            return
        if self.header_type == "TlvUcodeHeader":
            assert self.header is not None
            if self.header.build == 0:
                print(f"Header: version {self.header.version} {self.header.human_readable!r}", file=out)
            else:
                print(
                    f"Header: version {self.header.version} {self.header.human_readable!r} build {self.header.build:#x}",  # noqa
                    file=out,
                )
            return
        raise NotImplementedError(f"Unsupported FW header {self.header_type!r} ({self.header!r})")

    @classmethod
    def print_entry(cls, entry: Container, out: Optional[TextIO] = None, show_hexdump: bool = True) -> None:
        if out is None:
            out = sys.stdout
        cls.decode_entry(entry, out=out, show_hexdump=show_hexdump)

    @staticmethod
    def decode_entry(
        entry: Container, out: Optional[TextIO] = None, show_hexdump: bool = True
    ) -> Tuple[UcodeTlvType, Any]:
        """Decode a UcodeTlv entry, eventually printing it"""
        entry_type = UcodeTlvType(int(entry.type_))
        entry_data = entry.data

        if entry_type == UcodeTlvType.INST and len(entry_data) == 4:  # 1
            # On Windows, INST entries contain a date, formatted as hexadecimal
            date_str = f"{entry_data[3]:02x}{entry_data[2]:02x}-{entry_data[1]:02x}-{entry_data[0]:02x}"
            print(f"- {entry_type} ({len(entry_data)} bytes): date {date_str}", file=out)
            return entry_type, entry_data
        elif entry_type in {
            UcodeTlvType.INST,  # 1
            UcodeTlvType.DATA,  # 2
            UcodeTlvType.INIT,  # 3
            UcodeTlvType.INIT_DATA,  # 4
            UcodeTlvType.BOOT,  # 5
            UcodeTlvType.WOWLAN_INST,  # 16
            UcodeTlvType.WOWLAN_DATA,  # 17
        }:
            if out is not None:
                if len(entry_data) <= 8:
                    hex_data = " ".join(f"{c:02x}" for c in entry_data)
                    print(f"- {entry_type} ({len(entry_data)} bytes): {hex_data}", file=out)
                elif len(entry_data) <= 64 and all(c == 0 or 32 <= c < 127 for c in entry_data):
                    data_string = entry_data.decode("ascii").rstrip("\0")
                    print(f"- {entry_type} ({len(entry_data)} bytes): {data_string!r}", file=out)
                else:
                    digest = hashlib.sha256(entry_data).hexdigest()
                    print(
                        f"- {entry_type} ({len(entry_data)} bytes): {len(entry_data):#x} bytes, sha256={digest}",
                        file=out,
                    )
                    if show_hexdump:
                        hex_data = " ".join(f"{c:02x}" for c in entry_data[: min(len(entry_data), 0x20)])
                        print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, entry_data

        if entry_type in {
            UcodeTlvType.PROBE_MAX_LEN,  # 6
            UcodeTlvType.RUNT_EVTLOG_SIZE,  # 9
            UcodeTlvType.INIT_EVTLOG_SIZE,  # 12
            UcodeTlvType.PAGING,  # 32
        }:
            assert len(entry_data) == 4
            value = Int32ul.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {value:#x} = {value:d} bytes", file=out)
            return entry_type, value

        if entry_type == UcodeTlvType.MEM_DESC:  # 7
            if len(entry_data) == 0:
                if out is not None:
                    print(f"- {entry_type} ({len(entry_data)} bytes): empty", file=out)
                return entry_type, None
            mem_desc = MemDesc.parse(entry_data)
            assert len(entry_data) == 8 + mem_desc.len == 8 + len(mem_desc.data)
            if out is not None:
                addr = mem_desc.addr
                size = len(mem_desc.data)
                digest = hashlib.sha256(mem_desc.data).hexdigest()
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): memory at {addr:08x}..{addr + size:08x} ({size:#x}={size} bytes, sha256={digest})",  # noqa
                    file=out,
                )
                if show_hexdump:
                    hex_data = " ".join(f"{c:02x}" for c in mem_desc.data[: min(len(mem_desc.data), 0x20)])
                    print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, mem_desc

        if entry_type in {
            UcodeTlvType.RUNT_EVTLOG_PTR,  # 8
            UcodeTlvType.RUNT_ERRLOG_PTR,  # 10
            UcodeTlvType.INIT_EVTLOG_PTR,  # 11
            UcodeTlvType.INIT_ERRLOG_PTR,  # 13
            UcodeTlvType.SDIO_ADMA_ADDR,  # 35, address for ADMA in SDIO mode
            UcodeTlvType.TCM_DEBUG_ADDRS,  # 65
        }:
            assert len(entry_data) == 4
            value = Hex(Int32ul).parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {value}", file=out)
            return entry_type, value

        if entry_type == UcodeTlvType.ENHANCE_SENS_TBL:  # 14
            assert len(entry_data) == 0
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): present", file=out)
            return entry_type, None

        if entry_type == UcodeTlvType.PHY_CALIBRATION_SIZE:  # 31
            assert len(entry_data) == 4
            phy_calibration_size = Int32ul.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {phy_calibration_size}", file=out)
            return entry_type, phy_calibration_size

        if entry_type == UcodeTlvType.FLAGS and len(entry_data) == 4:  # 18
            flags = Hex(Int32ul).parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {flags}", file=out)
                for bitpos in range(32):
                    if flags & (1 << bitpos):
                        try:
                            flag_name = UcodeTlvFlag(bitpos).name
                        except ValueError:
                            flag_name = "(unknown)"
                        print(f"        [{bitpos:2}] {flag_name}", file=out)
            return entry_type, flags

        if entry_type == UcodeTlvType.FLAGS and len(entry_data) == 8:  # 18
            # It is actually API_CHANGES_SET in DVM firmware
            assert len(entry_data) == UcodeApi.sizeof()
            api = UcodeApi.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): index={api.api_index} flags={api.api_flags}", file=out
                )
                for bitpos in range(32):
                    if api.api_flags & (1 << bitpos):
                        full_bitpos = 32 * api.api_index + bitpos
                        try:
                            api_name = UcodeTlvApi(full_bitpos).name
                        except ValueError:
                            api_name = "(unknown)"
                        print(f"        [{full_bitpos:2}] {api_name}", file=out)
            return entry_type, api

        if entry_type in {UcodeTlvType.SEC_RT, UcodeTlvType.SECURE_SEC_RT}:  # 19, 24 "Runtime" or "Regular" microcode
            section = SecData.parse(entry_data)
            assert len(entry_data) == 4 + len(section.data)
            if out is not None:
                addr = section.addr
                if addr == 0xAAAABBBB and section.data == b"\x00\x00\x00\x00":
                    print(f"- {entry_type} ({len(entry_data)} bytes): {addr} => PAGING_SEPARATOR_SECTION", file=out)
                elif addr == 0xAAAABBBB and section.data == b"\xbb\xbb\xaa\xaa":
                    print(
                        f"- {entry_type} ({len(entry_data)} bytes): {addr} => PAGING_SEPARATOR_SECTION (duplicated)",
                        file=out,
                    )
                elif addr == 0xFFFFCCCC and section.data == b"\x00\x00\x00\x00":
                    print(f"- {entry_type} ({len(entry_data)} bytes): {addr} => CPU1_CPU2_SEPARATOR_SECTION", file=out)
                elif len(entry_data) == 8:
                    print(f"- {entry_type} ({len(entry_data)} bytes): {addr}, 4 bytes: {section.data.hex()}", file=out)
                else:
                    size = len(section.data)
                    digest = hashlib.sha256(section.data).hexdigest()
                    print(
                        f"- {entry_type} ({len(entry_data)} bytes): runtime ucode at {addr:08x}..{addr + size:08x} ({size:#x}={size} bytes, sha256={digest})",  # noqa
                        file=out,
                    )
                    if show_hexdump:
                        hex_data = " ".join(f"{c:02x}" for c in section.data[: min(len(section.data), 0x20)])
                        print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, section

        if entry_type in {UcodeTlvType.SEC_INIT, UcodeTlvType.SECURE_SEC_INIT}:  # 20, 25
            section = SecData.parse(entry_data)
            assert len(entry_data) == 4 + len(section.data)
            if out is not None:
                addr = section.addr
                size = len(section.data)
                digest = hashlib.sha256(section.data).hexdigest()
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): init ucode at {addr:08x}..{addr + size:08x} ({size:#x}={size} bytes, sha256={digest})",  # noqa
                    file=out,
                )
                if show_hexdump:
                    hex_data = " ".join(f"{c:02x}" for c in section.data[: min(len(section.data), 0x20)])
                    print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, section

        if entry_type in {UcodeTlvType.SEC_WOWLAN, UcodeTlvType.SECURE_SEC_WOWLAN}:  # 21, 26
            section = SecData.parse(entry_data)
            assert len(entry_data) == 4 + len(section.data)
            if out is not None:
                addr = section.addr
                size = len(section.data)
                digest = hashlib.sha256(section.data).hexdigest()
                hex_data = " ".join(f"{c:02x}" for c in section.data[: min(len(entry_data), 0x20)])
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): wowlan ucode at {addr:08x}..{addr + size:08x} ({size:#x}={size} bytes, sha256={digest})",  # noqa
                    file=out,
                )
                if show_hexdump:
                    hex_data = " ".join(f"{c:02x}" for c in section.data[: min(len(section.data), 0x20)])
                    print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, section

        if entry_type == UcodeTlvType.DEF_CALIB:  # 22
            assert len(entry_data) == TlvCalibData.sizeof()
            def_calib = TlvCalibData.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): ucode_type={def_calib.ucode_type} flow_trigger={def_calib.flow_trigger} event_trigger={def_calib.event_trigger}",  # noqa
                    file=out,
                )
                if def_calib.flow_trigger:
                    print("    flow_trigger:", file=out)
                    for bitpos in range(32):
                        bitmask = 1 << bitpos
                        if def_calib.flow_trigger & bitmask:
                            print(
                                f"        [{bitpos:2}] {CalibCfg(bitmask).name or 'unknown'} = {bitmask:#x}", file=out
                            )
                if def_calib.event_trigger:
                    print("    event_trigger:", file=out)
                    for bitpos in range(32):
                        bitmask = 1 << bitpos
                        if def_calib.event_trigger & bitmask:
                            print(
                                f"        [{bitpos:2}] {CalibCfg(bitmask).name or 'unknown'} = {bitmask:#x}", file=out
                            )
            return entry_type, def_calib

        if entry_type == UcodeTlvType.PHY_SKU:  # 23
            assert len(entry_data) == 4
            phy_config = Hex(Int32ul).parse(entry_data)
            if out is not None:
                radio_type = phy_config & 0x00000003
                radio_step = (phy_config & 0x0000000C) >> 2
                radio_dash = (phy_config & 0x00000030) >> 4
                valid_tx_ant = (phy_config & 0x000F0000) >> 16
                valid_rx_ant = (phy_config & 0x00F00000) >> 20
                chain_sad_enabled = (phy_config & 0x00800000) >> 23
                chain_sad_ant_a = (phy_config & 0x01000000) >> 24
                chain_sad_ant_b = (phy_config & 0x02000000) >> 25
                shared_clk = (phy_config & 0x80000000) >> 31
                desc = f"radio:type={radio_type},step={radio_step},dash={radio_dash} valid_tx_ant={valid_tx_ant} valid_rx_ant={valid_rx_ant}"  # noqa
                if chain_sad_enabled or chain_sad_ant_a or chain_sad_ant_b:
                    desc += f" chain_sad:enabled={chain_sad_enabled},ant_a={chain_sad_ant_a},ant_b={chain_sad_ant_b}"
                if shared_clk:
                    desc += f" shared_clk={shared_clk}"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): {phy_config} ({desc})",
                    file=out,
                )
            return entry_type, phy_config

        if entry_type == UcodeTlvType.NUM_OF_CPU:  # 27
            assert len(entry_data) == 4
            num_of_cpu = Int32ul.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {num_of_cpu}", file=out)
            return entry_type, num_of_cpu

        if entry_type == UcodeTlvType.CSCHEME:  # 28
            count = Int8ul.parse(entry_data[:1])
            expected_size = 1 + count * CipherScheme.sizeof()
            assert len(entry_data) >= expected_size
            assert entry_data[expected_size:] == b"\0" * (len(entry_data) - expected_size)
            cschemes = Array(count, CipherScheme).parse(entry_data[1:])
            if out is not None:
                if count == 0:
                    print(f"- {entry_type} ({len(entry_data)} bytes): empty", file=out)
                else:
                    print(f"- {entry_type} ({len(entry_data)} bytes, {count} entries):", file=out)
                    for cs in cschemes:
                        if count > 1:
                            print("    Scheme:", file=out)
                        for key, value in cs.items():
                            if not key.startswith("_"):
                                print(f"        {key} = {value}", file=out)
            return entry_type, cschemes

        if entry_type == UcodeTlvType.API_CHANGES_SET:  # 29
            assert len(entry_data) == UcodeApi.sizeof()
            api = UcodeApi.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): index={api.api_index} flags={api.api_flags}", file=out
                )
                for bitpos in range(32):
                    if api.api_flags & (1 << bitpos):
                        full_bitpos = 32 * api.api_index + bitpos
                        try:
                            api_name = UcodeTlvApi(full_bitpos).name
                        except ValueError:
                            api_name = "(unknown)"
                        print(f"        [{full_bitpos:2}] {api_name}", file=out)
            return entry_type, api

        if entry_type == UcodeTlvType.ENABLED_CAPABILITIES:  # 30
            assert len(entry_data) == UcodeCapa.sizeof()
            capa = UcodeCapa.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): index={capa.api_index} capa={capa.api_capa}", file=out
                )
                for bitpos in range(32):
                    if capa.api_capa & (1 << bitpos):
                        full_bitpos = 32 * capa.api_index + bitpos
                        try:
                            capa_name = UcodeTlvCapa(full_bitpos).name
                        except ValueError:
                            capa_name = "(unknown)"
                        print(f"        [{full_bitpos:2}] {capa_name}", file=out)
            return entry_type, capa

        if entry_type == UcodeTlvType.N_SCAN_CHANNELS:  # 31
            assert len(entry_data) == 4
            n_scan_channels = Int32ul.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {n_scan_channels}", file=out)
            return entry_type, n_scan_channels

        if entry_type == UcodeTlvType.SEC_RT_USNIFFER:  # 34
            section = SecData.parse(entry_data)
            assert len(entry_data) == 4 + len(section.data)
            if out is not None:
                addr = section.addr
                size = len(section.data)
                digest = hashlib.sha256(section.data).hexdigest()
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): usniffer ucode at {addr:08x}..{addr + size:08x} ({size:#x}={size} bytes, sha256={digest})",  # noqa
                    file=out,
                )
                if show_hexdump:
                    hex_data = " ".join(f"{c:02x}" for c in section.data[: min(len(section.data), 0x20)])
                    print(f"    Hexdump of start: {hex_data}", file=out)
            return entry_type, section

        if entry_type == UcodeTlvType.FW_VERSION:  # 36
            assert len(entry_data) == FwVersion.sizeof()
            ver = FwVersion.parse(entry_data)
            if out is not None:
                # Format the minor version as hexadecimal if it is high enough
                ver_minor = str(ver.minor) if ver.minor < 0x1000000 else f"{ver.minor:08x}"
                print(f"- {entry_type} ({len(entry_data)} bytes): {ver.major}.{ver_minor}.{ver.local_comp}", file=out)
            return entry_type, ver

        if entry_type == UcodeTlvType.FW_DBG_DEST:  # 38
            if entry_data[0] == 0:
                dest = FwDbgDestTlvV1.parse(entry_data)
                assert len(entry_data) == 0x18 + 0xC * len(dest.reg_ops)
            else:
                dest = FwDbgDestTlvV1.parse(entry_data)
                assert len(entry_data) == 0x14 + 0xC * len(dest.reg_ops)
            if out is not None:
                if dest.version == 0:
                    print(
                        f"- {entry_type} ({len(entry_data)} bytes): version={dest.version} monitor_mode={dest.monitor_mode} size_power={dest.size_power} base_reg={dest.base_reg} end_reg={dest.end_reg} write_ptr_reg={dest.write_ptr_reg} wrap_count={dest.wrap_count} base_shift={dest.base_shift} end_shift={dest.end_shift}",  # noqa
                        file=out,
                    )
                else:
                    print(
                        f"- {entry_type} ({len(entry_data)} bytes): version={dest.version} monitor_mode={dest.monitor_mode} size_power={dest.size_power} cfg_reg={dest.cfg_reg} write_ptr_reg={dest.write_ptr_reg} wrap_count={dest.wrap_count} base_shift={dest.base_shift} end_shift={dest.end_shift}",  # noqa
                        file=out,
                    )
                for op in dest.reg_ops:
                    print(f"    op {op.op}: addr={op.addr} val={op.val}")
            return entry_type, dest

        if entry_type == UcodeTlvType.FW_DBG_CONF:  # 39
            conf = FwDbgConfTlv.parse(entry_data)
            assert len(entry_data) == 4 + sum(4 + len(c.data) for c in conf.hcmd)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes, {len(conf.hcmd)} entries): id={conf.id} usniffer={conf.usniffer} num_of_hcmds={conf.num_of_hcmds}",  # noqa
                    file=out,
                )
                for idx, cmd in enumerate(conf.hcmd):
                    print(f"    [{idx:2d}] id={cmd.id} data[{cmd.len}]={cmd.data.hex()}", file=out)
                    # Decode the entry with some asserts to detect new use-cases
                    assert int(cmd.id) == LegacyCmds.LDBG_CONFIG_CMD
                    # Linux 5.1 defines LDBG_CFG_COMMAND_SIZE = 80 since
                    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e6aeeb4f45178197c956a5795f49648db67607bd
                    assert cmd.len == 80
                    cfg_cmd_type = Int32ul.parse(cmd.data)
                    print(f"      - type = {cfg_cmd_type:#x}", file=out)
                    # Then, the remaining of the command is not documented.
            return entry_type, conf

        if entry_type == UcodeTlvType.CMD_VERSIONS:  # 48
            versions = GreedyRange(CmdVersion).parse(entry_data)
            assert len(entry_data) == len(versions) * CmdVersion.sizeof()
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes, {len(versions)} entries):", file=out)
                for ver in versions:
                    try:
                        group_name = MvmCommandGroups(ver.group).name
                        group_str = f"{group_name}({ver.group:#x})"
                    except ValueError:
                        group_str = str(ver.group)
                    try:
                        cmd_name = GROUP_CMD_ENUM[ver.group](ver.cmd).name
                        grpcmd_str = f"{group_str}.{cmd_name}({ver.cmd})"
                    except (KeyError, ValueError):
                        grpcmd_str = f"{group_str}.{ver.cmd}"
                    print(
                        f"    {grpcmd_str:52s} cmd_ver={ver.cmd_ver:2d} notif_ver={ver.notif_ver:2d}",  # noqa
                        file=out,
                    )
            return entry_type, versions

        if entry_type == UcodeTlvType.FW_GSCAN_CAPA:  # 50
            if len(entry_data) == FwGscanCapabilitiesOld.sizeof():
                capa = FwGscanCapabilitiesOld.parse(entry_data)
            else:
                assert len(entry_data) == FwGscanCapabilities.sizeof()
                capa = FwGscanCapabilities.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes):", file=out)
                for key, value in capa.items():
                    if not key.startswith("_"):
                        print(f"    {key} = {value}", file=out)
            return entry_type, capa

        if entry_type == UcodeTlvType.FW_MEM_SEG:  # 51
            assert len(entry_data) == FwDbgMemSegTlv.sizeof()
            seg = FwDbgMemSegTlv.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): data_type={seg.data_type:d} at {seg.ofs:08x}..{seg.ofs + seg.len:08x} ({seg.len:#x}={seg.len:d} bytes)",  # noqa
                    file=out,
                )
            return entry_type, seg

        if entry_type == UcodeTlvType.UMAC_DEBUG_ADDRS:  # 54
            assert len(entry_data) == UmacDebugAddrs.sizeof()
            umac_debug_addrs = UmacDebugAddrs.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): error_info_addr={umac_debug_addrs.error_info_addr} dbg_print_buff_addr={umac_debug_addrs.dbg_print_buff_addr}",  # noqa
                    file=out,
                )
            return entry_type, umac_debug_addrs

        if entry_type == UcodeTlvType.LMAC_DEBUG_ADDRS:  # 55
            assert len(entry_data) == LmacDebugAddrs.sizeof()
            lmac_debug_addrs = LmacDebugAddrs.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes):", file=out)
                for key, value in lmac_debug_addrs.items():
                    if not key.startswith("_"):
                        print(f"    {key} = {value}", file=out)
            return entry_type, lmac_debug_addrs

        if entry_type == UcodeTlvType.FW_RECOVERY_INFO:  # 57
            assert len(entry_data) == FwRecoveryInfo.sizeof()
            recovery_info = FwRecoveryInfo.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): addr={recovery_info.addr} size={recovery_info.size}",
                    file=out,
                )
            return entry_type, recovery_info

        if entry_type == UcodeTlvType.HW_TYPE:  # 58
            assert len(entry_data) == HwType.sizeof()
            hw_type = HwType.parse(entry_data)
            if out is not None:
                try:
                    mac_type_str = CfgMacType(int(hw_type.mac_type)).name
                except ValueError:
                    mac_type_str = str(hw_type.mac_type)
                try:
                    rf_type_str = CfgRfType(int(hw_type.rf_type)).name
                except ValueError:
                    rf_type_str = str(hw_type.rf_type)
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): mac_type={mac_type_str} rf_type={rf_type_str}", file=out
                )
            return entry_type, hw_type

        if entry_type == UcodeTlvType.FW_FSEQ_VERSION:  # 60
            assert len(entry_data) == 52
            version = entry_data[:32].decode("ascii").rstrip("\0")
            sha1 = entry_data[32:].decode("ascii").rstrip("\0")
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): version={version!r} sha1={sha1!r}", file=out)
            return entry_type, (version, sha1)

        if entry_type == UcodeTlvType.PHY_INTEGRATION_VERSION:  # 61
            assert len(entry_data) == 40
            phy_int_version = entry_data.decode("ascii").rstrip("\0")
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {phy_int_version!r}", file=out)
            return entry_type, phy_int_version

        if entry_type == UcodeTlvType.PNVM_VERSION:  # 62
            assert len(entry_data) == 4
            pnvm_version = Hex(Int32ul).parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {pnvm_version}", file=out)
            return entry_type, pnvm_version

        if entry_type == UcodeTlvType.PNVM_SKU:  # 64
            assert len(entry_data) == SkuId.sizeof()
            sku_id = SkuId.parse(entry_data)
            if out is not None:
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): {sku_id.data[0]:#x} {sku_id.data[1]:#x} {sku_id.data[2]:#x}",  # noqa
                    file=out,
                )
            return entry_type, sku_id

        if entry_type in {UcodeTlvType.SEC_TABLE_ADDR, UcodeTlvType.D3_KEK_KCK_ADDR}:  # 66, 67
            assert len(entry_data) == FwDumpExclude.sizeof()
            excl = FwDumpExclude.parse(entry_data)
            if out is not None:
                if excl.addr == 0:
                    print(f"- {entry_type} ({len(entry_data)} bytes): addr={excl.addr:d} size={excl.size:d}", file=out)
                else:
                    print(f"- {entry_type} ({len(entry_data)} bytes): addr={excl.addr} size={excl.size}", file=out)
            return entry_type, excl

        if entry_type == UcodeTlvType.FW_NUM_STATIONS:  # 0x100
            assert len(entry_data) == 4
            num_stations = Int32ul.parse(entry_data)
            if out is not None:
                print(f"- {entry_type} ({len(entry_data)} bytes): {num_stations}", file=out)
            return entry_type, num_stations

        if entry_type == UcodeTlvType.TYPE_DEBUG_INFO:  # 0x1000005
            assert len(entry_data) == FwIniDebugInfoTlv.sizeof()
            debug_info = FwIniDebugInfoTlv.parse(entry_data)
            if out is not None:
                try:
                    domain_str = FwIniDbgDomain(int(debug_info.domain)).name
                except ValueError:
                    domain_str = f"{debug_info.domain:#010x}"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): domain={domain_str} image_type={debug_info.image_type} debug_cfg_name={debug_info.debug_cfg_name!r}",  # noqa
                    file=out,
                )
            return entry_type, debug_info

        if entry_type == UcodeTlvType.TYPE_BUFFER_ALLOCATION:  # 0x1000006
            assert len(entry_data) == FwIniAllocationTlv.sizeof()
            buf_alloc = FwIniAllocationTlv.parse(entry_data)
            if out is not None:
                try:
                    domain_str = FwIniDbgDomain(int(buf_alloc.domain)).name
                except ValueError:
                    domain_str = f"{buf_alloc.domain:#010x}"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): domain={domain_str} alloc_id={buf_alloc.alloc_id} buf_location={buf_alloc.buf_location} req_size={buf_alloc.req_size} max_frags_num={buf_alloc.max_frags_num} min_size={buf_alloc.min_size}",  # noqa
                    file=out,
                )
            return entry_type, buf_alloc

        if entry_type == UcodeTlvType.TYPE_HCMD:  # 0x1000007
            hcmd = FwInitHcmdTlv.parse(entry_data)
            if out is not None:
                try:
                    domain_str = FwIniDbgDomain(int(hcmd.domain)).name
                except ValueError:
                    domain_str = f"{hcmd.domain:#010x}"
                try:
                    group_name = MvmCommandGroups(hcmd.hcmd_group).name
                    group_str = f"{group_name}({hcmd.hcmd_group:#x})"
                except ValueError:
                    group_str = str(hcmd.hcmd_group)
                try:
                    cmd_name = GROUP_CMD_ENUM[hcmd.hcmd_group](hcmd.hcmd_id).name
                    grpcmd_str = f"{group_str}.{cmd_name}({hcmd.hcmd_id})"
                except (KeyError, ValueError):
                    grpcmd_str = f"{group_str}.{hcmd.hcmd_id}"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): domain={domain_str} time_point={hcmd.time_point} period_msec={hcmd.period_msec} hcmd={grpcmd_str} data[{len(hcmd.data)}]={hcmd.data.hex()}",  # noqa
                    file=out,
                )
            return entry_type, hcmd

        if entry_type == UcodeTlvType.TYPE_REGIONS:  # 0x1000008
            region = FwIniRegionTlv.parse(entry_data)
            if out is not None:
                regtype = FwIniRegionType(int(region.type_))
                regtype_desc = regtype.name
                if region.sub_type_ver:
                    regtype_desc += f".{region.sub_type}.{region.sub_type_ver}"
                elif region.sub_type:
                    regtype_desc += f".{region.sub_type}"
                if regtype == FwIniRegionType.DEVICE_MEMORY and region.sub_type:
                    regtype_desc += f" ({FwIniRegionDeviceMemorySubtype(region.sub_type).name})"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): id={region.id_} name={region.name!r} type={regtype_desc} domain={region.domain} version={region.version}",  # noqa
                    file=out,
                )
                if any(x != 0 for x in region.regconf_union):
                    if regtype in {
                        FwIniRegionType.DEVICE_MEMORY,
                        FwIniRegionType.PERIPHERY_MAC,
                        FwIniRegionType.PERIPHERY_PHY,
                        FwIniRegionType.PERIPHERY_AUX,
                        FwIniRegionType.PAGING,
                        FwIniRegionType.CSR,
                        FwIniRegionType.DRAM_IMR,
                        FwIniRegionType.PCI_IOSF_CONFIG,
                        FwIniRegionType.DBGI_SRAM,
                        FwIniRegionType.PERIPHERY_SNPS_DPHYIP,
                    }:
                        # struct iwl_fw_ini_region_dev_addr dev_addr
                        dev_addr = FwIniRegionDevAddr.parse(region.regconf_union)
                        print(f"    dev_addr: offset={dev_addr.offset} size={dev_addr.size}", file=out)
                    elif regtype in {
                        FwIniRegionType.TXF,
                        FwIniRegionType.RXF,
                    }:
                        # struct iwl_fw_ini_region_fifos fifos
                        fifos = FwIniRegionFifos.parse(region.regconf_union)
                        print(
                            f"    fifos: fids=({fifos.fid0}, {fifos.fid1}) hdr_only={fifos.hdr_only} offset={fifos.offset}",  # noqa
                            file=out,
                        )
                    elif regtype in {
                        FwIniRegionType.LMAC_ERROR_TABLE,
                        FwIniRegionType.UMAC_ERROR_TABLE,
                    }:
                        # struct iwl_fw_ini_region_err_table err_table
                        err_table = FwIniRegionErrTable.parse(region.regconf_union)
                        print(
                            f"    err_table: version={err_table.version} base_addr={err_table.base_addr} size={err_table.size} offset={err_table.offset}",  # noqa
                            file=out,
                        )
                    elif regtype == FwIniRegionType.INTERNAL_BUFFER:
                        # struct iwl_fw_ini_region_internal_buffer internal_buffer
                        internal_buffer = FwIniRegionInternalBuffer.parse(region.regconf_union)
                        print(
                            f"    internal_buffer: alloc_id={internal_buffer.alloc_id} base_addr={internal_buffer.base_addr} size={internal_buffer.size}",  # noqa
                            file=out,
                        )
                    elif regtype == FwIniRegionType.DRAM_BUFFER:
                        # __le32 dram_alloc_id
                        dram_alloc_id = Int32ul.parse(region.regconf_union[:4])
                        print(f"    dram_alloc_id = {dram_alloc_id}", file=out)
                        assert region.regconf_union[4:] == b"\0" * 12
                    elif regtype == FwIniRegionType.TLV:
                        # __le32 tlv_mask
                        tlv_mask = Int32ul.parse(region.regconf_union[:4])
                        print(f"    tlv_mask = {tlv_mask:#x}", file=out)
                        assert region.regconf_union[4:] == b"\0" * 12
                    elif regtype == FwIniRegionType.SPECIAL_DEVICE_MEMORY:
                        # iwl_fw_ini_region_special_device_memory special_mem
                        special_mem = FwIniRegionSpecialDeviceMemory.parse(region.regconf_union)
                        print(
                            f"    special_mem: type={special_mem.type_} version={special_mem.version} base_addr={special_mem.base_addr} size={special_mem.size} offset={special_mem.offset}",  # noqa
                            file=out,
                        )
                    else:
                        print(f"    union bytes: {region.regconf_union.hex()}", file=out)
                        raise NotImplementedError(f"Unimplemented region type {regtype!r}")
                if region.addr:
                    if len(region.addr) < 16:
                        print(f"    addresses[{len(region.addr)}] = {' '.join(hex(a) for a in region.addr)}", file=out)
                    else:
                        print(f"    addresses[{len(region.addr)}] =", file=out)
                        for idx in range(0, len(region.addr), 8):
                            end_idx = min(idx + 8, len(region.addr))
                            print("        " + " ".join(f"{a:#010x}" for a in region.addr[idx:end_idx]), file=out)
            return entry_type, region

        if entry_type == UcodeTlvType.TYPE_TRIGGERS:  # 0x1000009
            trigger = FwInitTriggerTlv.parse(entry_data)
            if out is not None:
                try:
                    domain_str = FwIniDbgDomain(int(trigger.domain)).name
                except ValueError:
                    domain_str = f"{trigger.domain:#010x}"
                desc = f"domain={domain_str}"
                desc += f" time_point={trigger.time_point}"
                desc += f" trigger_reason={trigger.trigger_reason}"
                desc += f" apply_policy={trigger.apply_policy}"
                if trigger.dump_delay != 0:
                    desc += f" dump_delay={trigger.dump_delay}"
                if trigger.occurrences != 0:
                    desc += f" occurrences={trigger.occurrences}"
                if trigger.reserved != 0:
                    desc += f" reserved={trigger.reserved}"
                if trigger.ignore_consec != 0:
                    desc += f" ignore_consec={trigger.ignore_consec}"
                if trigger.reset_fw != 0:
                    desc += f" reset_fw={trigger.reset_fw}"
                if trigger.multi_dut != 0:
                    desc += f" multi_dut={trigger.multi_dut}"
                if trigger.regions_mask != 0:
                    desc += f" regions_mask={trigger.regions_mask}"
                if trigger.data:
                    desc += f" data={trigger.data.hex()}"
                print(
                    f"- {entry_type} ({len(entry_data)} bytes): {desc}",
                    file=out,
                )
            return entry_type, trigger

        # Fallback description
        if out is not None:
            if len(entry_data) > 0:
                print(f"- {entry_type} ({len(entry_data)} bytes):", file=out)
                if show_hexdump:
                    hex_data = " ".join(f"{c:02x}" for c in entry_data[: min(len(entry_data), 0x20)])
                    print(f"    Hexdump: {hex_data}", file=out)
            else:
                print(f"- {entry_type} ({len(entry_data)} bytes): empty", file=out)
        return entry_type, entry_data

    def get_signatures(self) -> List[Tuple[UcodeTlvType, int, Container]]:
        """Retrieve sections with signature information"""
        signatures: List[Tuple[UcodeTlvType, int, Container]] = []
        current_signature_section: Optional[Container] = None
        current_signature_algid = None
        current_signature_hash = None
        current_signature_entry_type = None
        current_signature_sec_index = 0
        for entry in self.entries:
            if int(entry.type_) not in {
                UcodeTlvType.MEM_DESC,
                UcodeTlvType.SEC_RT,
                UcodeTlvType.SEC_INIT,
                UcodeTlvType.SEC_WOWLAN,
                UcodeTlvType.SECURE_SEC_RT,
                UcodeTlvType.SECURE_SEC_INIT,
                UcodeTlvType.SECURE_SEC_WOWLAN,
                UcodeTlvType.SEC_RT_USNIFFER,
            }:
                continue
            entry_type, entry_data = self.decode_entry(entry)
            # Skip empty MEM_DESC entries
            if entry_type == UcodeTlvType.MEM_DESC and entry_data is None:
                continue
            entry_addr = entry_data.addr
            entry_size = len(entry_data.data)
            # print(f"{entry_type} {entry_addr:#010x}..{entry_addr + entry_size:#010x}")
            if current_signature_section is None:
                # Skip specials sections
                if entry_addr in {0, 1, 2, 3, 0xAAAABBBB, 0xFFFFCCCC} and entry_size == 4:
                    continue
                # Some firmware include data from the previous section in a
                # CPU1_CPU2_SEPARATOR_SECTION section
                if entry_addr == 0xFFFFCCCC and entry_size == 0x20:
                    continue
                # Parse a new signature, if it is not too large
                if entry_size >= 0x1000:
                    # Detect firmware with no signtaure information,
                    # if they directly start with an address which is known to not be CSS
                    if entry_addr == 0x00800000 and not signatures:
                        return []
                    raise ValueError(
                        f"Trying to parse a large CSS of {entry_size} bytes ({entry_type}, {entry_addr:#010x})"
                    )
                if entry_data.data.startswith(b"\x06\0\0\0\xa1\0\0\0"):
                    current_signature_algid = "rsa2048"
                    current_signature_section = CodeSignatureSectionRsa2048.parse(entry_data.data)
                    current_signature_hash = hashlib.sha256()
                    assert current_signature_section.reserved == b"\0" * len(current_signature_section.reserved)
                elif entry_data.data.startswith(b"\x06\0\0\0\x50\0\0\0"):
                    current_signature_algid = "secp384r1"
                    current_signature_section = CodeSignatureSectionEcSecp384r1.parse(entry_data.data)
                    current_signature_hash = hashlib.sha384()
                    assert current_signature_section.reserved == b"\0" * len(current_signature_section.reserved)
                    assert current_signature_section.padding == b"\0" * len(current_signature_section.padding)
                else:
                    raise NotImplementedError(f"Unknown module type: {entry_data.data[:0x20].hex()}")
                assert len(current_signature_section.sections) == current_signature_section.num_sections
                css_end = 0x288 + current_signature_section.num_sections * 0x10
                assert css_end <= entry_size
                assert entry_data.data[css_end:] == b"\0" * (entry_size - css_end)
                for sect_info in current_signature_section.sections:
                    assert sect_info.flags == 7  # Unknown flags
                    assert sect_info.size_plus_8 == sect_info.size + 8
                current_signature_hash.update(entry_data.data[:0x80])
                current_signature_hash.update(entry_data.data[0x284:css_end])
                current_signature_entry_type = entry_type
                current_signature_sec_index = 0
                signatures.append((entry_type, entry_addr, current_signature_section))
            else:
                if entry_type != current_signature_entry_type:
                    raise ValueError(
                        f"Unexpected entry {entry_type} while analyzing signatures for {current_signature_entry_type}"
                    )
                assert current_signature_section is not None
                assert current_signature_hash is not None
                expected_info = current_signature_section.sections[current_signature_sec_index]
                if entry_addr != expected_info.addr:
                    raise ValueError(
                        f"Unexpected address for entry {entry_type}: {entry_addr:#x} != {expected_info.addr:#x}"
                    )
                if entry_size != expected_info.size:
                    raise ValueError(
                        f"Unexpected size for entry {entry_type} at {entry_addr:#x}: {entry_size:#x} != {expected_info.size:#x}"  # noqa
                    )
                current_signature_hash.update(entry_data.data)
                current_signature_sec_index += 1
                if current_signature_sec_index == current_signature_section.num_sections:
                    # Finalize the signature verification
                    computed_digest = current_signature_hash.digest()
                    if current_signature_algid == "rsa2048":
                        rsa_modulus = int.from_bytes(current_signature_section.rsa_modulus, "little")
                        rsa_pubexp = current_signature_section.rsa_pubexp
                        rsa_signature = int.from_bytes(current_signature_section.rsa_signature, "little")
                        signed_digest = pow(rsa_signature, rsa_pubexp, rsa_modulus).to_bytes(256, "big")
                        if signed_digest != PKCS1_SHA256_PREFIX + computed_digest:
                            raise ValueError(
                                f"Unexpected SHA256 digest: {computed_digest.hex()} != {signed_digest.hex()}"
                            )
                    elif current_signature_algid == "secp384r1":
                        ec_pub_x = int.from_bytes(current_signature_section.ec_pub_x, "little")
                        ec_pub_y = int.from_bytes(current_signature_section.ec_pub_y, "little")
                        ecdsa_r = int.from_bytes(current_signature_section.ec_signature_r, "little")
                        ecdsa_s = int.from_bytes(current_signature_section.ec_signature_s, "little")

                        # Ensure that the public point is on the curve
                        assert (
                            pow(ec_pub_y, 2, SECP384R1_PRIME)
                            == (pow(ec_pub_x, 3, SECP384R1_PRIME) + SECP384R1_A * ec_pub_x + SECP384R1_B)
                            % SECP384R1_PRIME
                        )

                        # Verify the signature
                        ec_pubkey = (
                            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.from_encoded_point(
                                cryptography.hazmat.primitives.asymmetric.ec.SECP384R1(),
                                b"\x04" + ec_pub_x.to_bytes(48, "big") + ec_pub_y.to_bytes(48, "big"),
                            )
                        )
                        ec_pubkey.verify(
                            cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(ecdsa_r, ecdsa_s),
                            computed_digest,
                            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
                                cryptography.hazmat.primitives.asymmetric.utils.Prehashed(
                                    cryptography.hazmat.primitives.hashes.SHA384()
                                )
                            ),
                        )
                    else:
                        raise NotImplementedError(f"Unimplemented signature algorithm {current_signature_algid}")
                    current_signature_algid = None
                    current_signature_section = None
        assert current_signature_section is None  # Ensure that all signatures were fully processed
        return signatures

    def print_signatures(self, out: Optional[TextIO] = None) -> None:
        signatures = self.get_signatures()
        if not signatures:
            print("No signature", file=out)
            return
        print(f"Signatures (count {len(signatures)}):", file=out)
        for entry_type, entry_addr, signature in signatures:
            date_str = f"{signature.date:08x}"
            date_str = f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:]}"
            sect_num_str = f"{signature.num_sections} {'sections' if signature.num_sections >= 2 else 'section'}"
            total_size = signature.size * 4
            if (
                signature.header_size == 0xA1
                and signature.header_version_major == 0
                and signature.header_version_minor == 1
            ):  # RSA 2048
                unk_str = f"unknown={signature.unknown_0x1c:#x},{signature.unknown_0x20:#x},{signature.unknown_0x24:#x},{signature.unknown_0x28:#x},{signature.unknown_0x2c:#x},{signature.unknown_0x30:#x}"  # noqa
                print(
                    f"- {entry_type} {entry_addr:#010x} (RSA-2048, {date_str}, {total_size:#x}={total_size} bytes, {sect_num_str}, {unk_str})",  # noqa
                    file=out,
                )
                print(f"    RSA modulus: 0x{signature.rsa_modulus[::-1].hex()}", file=out)
                print(f"    RSA pubexp: {signature.rsa_pubexp}", file=out)
                print(f"    RSA signature: 0x{signature.rsa_signature[::-1].hex()}", file=out)
                # TODO: understand the fields and rename them in the structure
                assert signature.unknown_0x1c == 0x40  # Signature length?
                assert signature.unknown_0x20 == 0x40  # Public key length?
                assert signature.unknown_0x24 == 1
                # signature.unknown_0x28 is the file version
                assert signature.unknown_0x2c in {0, 1}
                assert signature.unknown_0x30 in {0, 1, 2, 3, 4}  # Index in the file? Or kind?
            elif (
                signature.header_size == 0x50
                and signature.header_version_major == 0
                and signature.header_version_minor == 2
            ):  # EC secp384r1
                unk_str = f"unknown={signature.unknown_0x1c:#x},{signature.unknown_0x20:#x},{signature.unknown_0x24:#x},{signature.unknown_0x28:#x},{signature.unknown_0x2c:#x},{signature.unknown_0x30:#x},{signature.unknown_0x34:#x},{signature.unknown_0x38:#x}"  # noqa
                print(
                    f"- {entry_type} {entry_addr:#010x} (secp384r1, {date_str}, {total_size:#x}={total_size} bytes, {sect_num_str}, {unk_str})",  # noqa
                    file=out,
                )
                print(f"    EC pub x: 0x{signature.ec_pub_x[::-1].hex()}", file=out)
                print(f"    EC pub y: 0x{signature.ec_pub_y[::-1].hex()}", file=out)
                print(f"    EC signature r: 0x{signature.ec_signature_r[::-1].hex()}", file=out)
                print(f"    EC signature s: 0x{signature.ec_signature_s[::-1].hex()}", file=out)
                # TODO: understand the fields and rename in the structure
                assert signature.unknown_0x1c == 0x18
                assert signature.unknown_0x20 == 0xC
                assert signature.unknown_0x24 == 0xC
                assert signature.unknown_0x28 in {0, 0x100}
                assert signature.unknown_0x2c in {0, 1}
                assert signature.unknown_0x30 in {0, 1, 2, 3, 4, 5}
                # signature.unknown_0x34 is the file version
                assert signature.unknown_0x38 in {0, 3}
            else:
                raise NotImplementedError("Unimplemented signature algorithm")
            print(f"    {signature.num_sections} {'sections' if signature.num_sections >= 2 else 'section'}:", file=out)
            for sect_info in signature.sections:
                print(
                    f"        {sect_info.addr:#010x}..{sect_info.addr + sect_info.size:#010x} ({sect_info.size:#x}={sect_info.size:d} bytes)",  # noqa
                    file=out,
                )
                assert sect_info.flags == 7  # Unknown flags
                assert sect_info.size_plus_8 == sect_info.size + 8
            computed_total_size = (
                signature.header_size * 4
                + 4
                + signature.num_sections * 0x10
                + sum(sect_info.size for sect_info in signature.sections)
            )
            if computed_total_size != total_size:
                raise ValueError(f"Mismatched computed size {computed_total_size:#x} != declared {total_size:#x}")


def parse_wifi_fw(path: Path, with_hex: bool = False) -> None:
    for idx, fw in enumerate(IntelWifiFirmware.parse_all_file(path)):
        if idx > 0:
            print(f"---- Firmware #{idx} ----")
        fw.print_header()
        for entry in fw.entries:
            if with_hex:
                fw.print_entry(entry, show_hexdump=False)
                for iline in range(0, len(entry.data), 16):
                    hex_line = ""
                    asc_line = ""
                    for icol in range(16):
                        offset = iline + icol
                        if offset < len(entry.data):
                            byte = entry.data[offset]
                            hex_line += f"{byte:02x}"
                            asc_line += chr(byte) if 32 <= byte < 127 else "."
                        else:
                            hex_line += "  "
                        if icol & 1:
                            hex_line += " "
                    print(f"  {iline:06x}: {hex_line} {asc_line}")
            else:
                fw.print_entry(entry, show_hexdump=True)

        print("")
        fw.print_signatures()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse an Intel Wi-Fi firmware image")
    parser.add_argument(
        "fwfile",
        nargs="+",
        type=Path,
        help="path to a file such as /usr/lib/firmware/iwlwifi*.ucode",
    )
    parser.add_argument("-x", "--hex", action="store_true", help="Dump hexadecimal content of each TLV data")
    args = parser.parse_args()

    for fwfile in args.fwfile:
        print(f"Parsing {fwfile}")
        parse_wifi_fw(fwfile, with_hex=args.hex)
