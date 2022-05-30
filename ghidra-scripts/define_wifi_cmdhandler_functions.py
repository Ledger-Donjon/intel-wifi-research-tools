# SPDX-License-Identifier: MIT

# Define the functions handling host commands in iwlwifi firmware (ARCompact)
ram = currentProgram.getAddressFactory().getAddressSpace("ram")

# Update the program database
UPDATE_DB_REAL = not True
HAVE_UMAC = True  # Set to False when analyzing INIT microcode without UMAC

# Define types
byte_t = ghidra.program.model.data.ByteDataType()
void_t = ghidra.program.model.data.VoidDataType()
void_p_t = ghidra.program.model.data.PointerDataType(void_t)
void_pp_t = ghidra.program.model.data.PointerDataType(void_p_t)

if HAVE_UMAC:
    umac_hostcmd_entry_types = getDataTypes("UMAC_HOSTCMD_ENTRY")
    assert len(umac_hostcmd_entry_types) == 1
    umac_hostcmd_entry_t = umac_hostcmd_entry_types[0]
    assert umac_hostcmd_entry_t.getLength() == 6
    umac_hostcmd_entry_p_t = ghidra.program.model.data.PointerDataType(umac_hostcmd_entry_t)
    assert umac_hostcmd_entry_p_t.getLength() == 4

    # Get the function data type of UMAC host command handlers
    umac_hostcmd_handler_types = getDataTypes("UMAC_HOSTCMD_HANDLER")
    assert len(umac_hostcmd_handler_types) == 1
    umac_hostcmd_handler_t = umac_hostcmd_handler_types[0]

# Define commands and groups from https://elixir.bootlin.com/linux/v5.11/source/drivers/net/wireless/intel/iwlwifi/fw/api/commands.h
iwl_legacy_cmds = {
    0x01: "UCODE_ALIVE_NTFY",
    0x02: "REPLY_ERROR",
    0x03: "ECHO_CMD",
    0x04: "INIT_COMPLETE_NOTIF",
    0x08: "PHY_CONTEXT_CMD",
    0x09: "DBG_CFG",
    0x0c: "SCAN_CFG_CMD",
    0x0d: "SCAN_REQ_UMAC",
    0x0e: "SCAN_ABORT_UMAC",
    0x0f: "SCAN_COMPLETE_UMAC",
    0x13: "BA_WINDOW_STATUS_NOTIFICATION_ID",
    0x17: "ADD_STA_KEY",
    0x18: "ADD_STA",
    0x19: "REMOVE_STA",
    0x1a: "FW_GET_ITEM_CMD",
    0x1c: "TX_CMD",
    0x1d: "SCD_QUEUE_CFG",
    0x1e: "TXPATH_FLUSH",
    0x1f: "MGMT_MCAST_KEY",
    0x20: "WEP_KEY",
    0x25: "SHARED_MEM_CFG",
    0x27: "TDLS_CHANNEL_SWITCH_CMD",
    0x28: "MAC_CONTEXT_CMD",
    0x29: "TIME_EVENT_CMD",
    0x2a: "TIME_EVENT_NOTIFICATION",
    0x2b: "BINDING_CONTEXT_CMD",
    0x2c: "TIME_QUOTA_CMD",
    0x2d: "NON_QOS_TX_COUNTER_CMD",
    0x48: "LEDS_CMD",
    0x4e: "LQ_CMD",
    0x4f: "FW_PAGING_BLOCK_CMD",
    0x51: "SCAN_OFFLOAD_REQUEST_CMD",
    0x52: "SCAN_OFFLOAD_ABORT_CMD",
    0x53: "HOT_SPOT_CMD",
    0x56: "SCAN_OFFLOAD_PROFILES_QUERY_CMD",
    0x5c: "BT_COEX_UPDATE_REDUCED_TXP",
    0x5d: "BT_COEX_CI",
    0x6a: "PHY_CONFIGURATION_CMD",
    0x6b: "CALIB_RES_NOTIF_PHY_DB",
    0x6c: "PHY_DB_CMD",
    0x6d: "SCAN_OFFLOAD_COMPLETE",
    0x6e: "SCAN_OFFLOAD_UPDATE_PROFILES_CMD",
    0x77: "POWER_TABLE_CMD",
    0x78: "PSM_UAPSD_AP_MISBEHAVING_NOTIFICATION",
    0x7e: "REPLY_THERMAL_MNG_BACKOFF",
    0x83: "DC2DC_CONFIG_CMD",
    0x88: "NVM_ACCESS_CMD",
    0x90: "BEACON_NOTIFICATION",
    0x91: "BEACON_TEMPLATE_CMD",
    0x98: "TX_ANT_CONFIGURATION_CMD",
    0x9b: "BT_CONFIG",
    0x9c: "STATISTICS_CMD",
    0x9d: "STATISTICS_NOTIFICATION",
    0x9e: "EOSP_NOTIFICATION",
    0x9f: "REDUCE_TX_POWER_CMD",
    0xa1: "CARD_STATE_NOTIFICATION",
    0xa2: "MISSED_BEACONS_NOTIFICATION",
    0xa7: "TDLS_CONFIG_CMD",
    0xa9: "MAC_PM_POWER_TABLE",
    0xaa: "TDLS_CHANNEL_SWITCH_NOTIFICATION",
    0xb1: "MFUART_LOAD_NOTIFICATION",
    0xb3: "RSS_CONFIG_CMD",
    0xb5: "SCAN_ITERATION_COMPLETE_UMAC",
    0xc0: "REPLY_RX_PHY_CMD",
    0xc1: "REPLY_RX_MPDU_CMD",
    0xc2: "BAR_FRAME_RELEASE",
    0xc3: "FRAME_RELEASE",
    0xc5: "BA_NOTIF",
    0xc8: "MCC_UPDATE_CMD",
    0xc9: "MCC_CHUB_UPDATE_CMD",
    0xcb: "MARKER_CMD",
    0xce: "BT_PROFILE_NOTIFICATION",
    0xcf: "BCAST_FILTER_CMD",
    0xd0: "MCAST_FILTER_CMD",
    0xd1: "REPLY_SF_CFG_CMD",
    0xd2: "REPLY_BEACON_FILTERING_CMD",
    0xd3: "D3_CONFIG_CMD",
    0xd4: "PROT_OFFLOAD_CONFIG_CMD",
    0xd5: "OFFLOADS_QUERY_CMD",
    0xd6: "REMOTE_WAKE_CONFIG_CMD",
    0xd9: "MATCH_FOUND_NOTIFICATION",
    0xdd: "DTS_MEASUREMENT_NOTIFICATION",
    0xe0: "WOWLAN_PATTERNS",
    0xe1: "WOWLAN_CONFIGURATION",
    0xe2: "WOWLAN_TSC_RSC_PARAM",
    0xe3: "WOWLAN_TKIP_PARAM",
    0xe4: "WOWLAN_KEK_KCK_MATERIAL",
    0xe5: "WOWLAN_GET_STATUSES",
    0xe7: "SCAN_ITERATION_COMPLETE",
    0xed: "D0I3_END_CMD",
    0xee: "LTR_CONFIG",
    0xf6: "LDBG_CONFIG_CMD",
    0xf7: "DEBUG_LOG_MSG",
}
iwl_system_subcmd_ids = {
    0x00: "SHARED_MEM_CFG_CMD",
    0x01: "SOC_CONFIGURATION_CMD",
    0x03: "INIT_EXTENDED_CFG_CMD",
    0x07: "FW_ERROR_RECOVERY_CMD",
}
iwl_mac_conf_subcmd_ids = {
    0x03: "LOW_LATENCY_CMD",
    0x04: "CHANNEL_SWITCH_TIME_EVENT_CMD",
    0x05: "SESSION_PROTECTION_CMD",
    0xFA: "MISSED_VAP_NOTIF",
    0xFB: "SESSION_PROTECTION_NOTIF",
    0xFC: "PROBE_RESPONSE_DATA_NOTIF",
    0xFF: "CHANNEL_SWITCH_NOA_NOTIF",
}
iwl_phy_ops_subcmd_ids = {
    0x00: "CMD_DTS_MEASUREMENT_TRIGGER_WIDE",
    0x03: "CTDP_CONFIG_CMD",
    0x04: "TEMP_REPORTING_THRESHOLDS_CMD",
    0x05: "GEO_TX_POWER_LIMIT",
    0x07: "PER_PLATFORM_ANT_GAIN_CMD",
    0xFE: "CT_KILL_NOTIFICATION",
    0xFF: "DTS_MEASUREMENT_NOTIF_WIDE",
}
iwl_data_path_subcmd_ids = {
    0x00: "DQA_ENABLE_CMD",
    0x01: "UPDATE_MU_GROUPS_CMD",
    0x02: "TRIGGER_RX_QUEUES_NOTIF_CMD",
    0x07: "STA_HE_CTXT_CMD",
    0x0D: "RFH_QUEUE_CONFIG_CMD",
    0x0F: "TLC_MNG_CONFIG_CMD",
    0x13: "HE_AIR_SNIFFER_CONFIG_CMD",
    0x14: "CHEST_COLLECTOR_FILTER_CONFIG_CMD",
    0xF5: "RX_NO_DATA_NOTIF",
    0xF7: "TLC_MNG_UPDATE_NOTIF",
    0xFD: "STA_PM_NOTIF",
    0xFE: "MU_GROUP_MGMT_NOTIF",
    0xFF: "RX_QUEUES_NOTIFICATION",
}
iwl_location_subcmd_ids = {
    0x00: "TOF_RANGE_REQ_CMD",
    0x01: "TOF_CONFIG_CMD",
    0x02: "TOF_RANGE_ABORT_CMD",
    0x03: "TOF_RANGE_REQ_EXT_CMD",
    0x04: "TOF_RESPONDER_CONFIG_CMD",
    0x05: "TOF_RESPONDER_DYN_CONFIG_CMD",
    0xFA: "CSI_HEADER_NOTIFICATION",
    0xFB: "CSI_CHUNKS_NOTIFICATION",
    0xFC: "TOF_LC_NOTIF",
    0xFD: "TOF_RESPONDER_STATS",
    0xFE: "TOF_MCSI_DEBUG_NOTIF",
    0xFF: "TOF_RANGE_RESPONSE_NOTIF",
}
iwl_prot_offload_subcmd_ids = {
    0xFF: "STORED_BEACON_NTF",
}
iwl_regulatory_and_nvm_subcmd_ids = {
    0x00: "NVM_ACCESS_COMPLETE",
    0x01: "LARI_CONFIG_CHANGE",
    0x02: "NVM_GET_INFO",
    0x03: "TAS_CONFIG",
    0xFE: "PNVM_INIT_COMPLETE_NTFY",
}
iwl_debug_cmds = {
    0x00: "LMAC_RD_WR",
    0x01: "UMAC_RD_WR",
    0x03: "HOST_EVENT_CFG",
    0x07: "DBGC_SUSPEND_RESUME",
    0x08: "BUFFER_ALLOCATION",
    0xfe: "MFU_ASSERT_DUMP_NTF",
}
iwl_mvm_command_groups = {
    0x00: ("LEGACY", iwl_legacy_cmds),
    0x01: ("LEGACY", iwl_legacy_cmds),  # Legacy commands with LONG header, but same table
    0x02: ("SYSTEM", iwl_system_subcmd_ids),
    0x03: ("MAC_CONF", iwl_mac_conf_subcmd_ids),
    0x04: ("PHY_OPS", iwl_phy_ops_subcmd_ids),
    0x05: ("DATA_PATH", iwl_data_path_subcmd_ids),
    0x07: ("NAN", {}),
    0x08: ("LOCATION", iwl_location_subcmd_ids),
    0x0b: ("PROT_OFFLOAD", iwl_prot_offload_subcmd_ids),
    0x0c: ("REGULATORY_AND_NVM", iwl_regulatory_and_nvm_subcmd_ids),
    0x0f: ("DEBUG", iwl_debug_cmds),
}


def get_symbol_addr(name):
    symbols = currentProgram.symbolTable.getGlobalSymbols(name)
    if not symbols:
        raise RuntimeError("Symbol {!r} is not defined".format(name))
    if len(symbols) > 1:
        raise RuntimeError("Symbol {!r} is defined multiple times!".format(name))
    return symbols[0].getAddress()


def set_data_type(desc, addr, new_data_type):
    current_data = getDataAt(addr)
    if current_data is None:
        print("Defining {} data type: {} at {}".format(desc, new_data_type.toString(), addr))
        if UPDATE_DB_REAL:
            createData(addr, new_data_type)
    elif current_data.getDataType().toString() != new_data_type.toString():
        print("Setting {} data type: {} -> {} at {}".format(desc, current_data.getDataType().toString(), new_data_type.toString(), addr))
        if UPDATE_DB_REAL:
            removeData(current_data)
            createData(addr, new_data_type)


def describe_umac_secondary_index(value_idx):
    """Get a description from an index to a secondary table"""
    second_table_symbol_name = "g_UMAC_HOSTCMD_secondary_table"
    second_table_addr = get_symbol_addr(second_table_symbol_name)
    entry_addr = second_table_addr.addNoWrap(0xc * value_idx)
    task_id = getShort(entry_addr)
    expected_size = getShort(entry_addr.addNoWrap(2))
    direct_callback_raw = getInt(entry_addr.addNoWrap(4))
    queued_callback_raw = getInt(entry_addr.addNoWrap(8))

    if task_id == 0:
        task_desc = ""  # MAIN
    elif task_id == 1:
        task_desc = " in BACKGROUND"
    else:
        task_desc = " in task {:#x}".format(task_id)

    if direct_callback_raw != 0:
        addr = ram.getAddress(direct_callback_raw)
        sym = getSymbolAt(addr)
        direct_cb_desc = " direct at {} ({})".format(addr, sym)
    else:
        direct_cb_desc = ""

    if queued_callback_raw != 0:
        addr = ram.getAddress(queued_callback_raw)
        sym = getSymbolAt(addr)
        queued_cb_desc = " queued at {} ({})".format(addr, sym)
    else:
        queued_cb_desc = ""

    return "msgsize 0x{:x}{}{}{}".format(expected_size, task_desc, direct_cb_desc, queued_cb_desc)


def process_hostcmd_definitions(is_umac, is_negative):
    if is_umac:
        if is_negative:
            symbol_name = "g_UMAC_HOSTCMD_negative_handlers"
            cmdcount_symbol_name = "g_UMAC_HOSTCMD_cmdcount_by_negative_group"

            second_symbol_name = "g_UMAC_HOSTCMD_secondary_negative_cmdindex"
            second_cmdcount_symbol_name = "g_UMAC_HOSTCMD_secondary_cmdcount_by_negative_group"
        else:
            symbol_name = "g_UMAC_HOSTCMD_handlers"
            cmdcount_symbol_name = "g_UMAC_HOSTCMD_cmdcount_by_group"

            second_symbol_name = "g_UMAC_HOSTCMD_secondary_cmdindex"
            second_cmdcount_symbol_name = "g_UMAC_HOSTCMD_secondary_cmdcount_by_group"
    else:
        if is_negative:
            symbol_name = "g_LMAC_HOSTCMD_negative_handlers"
            cmdcount_symbol_name = "g_LMAC_HOSTCMD_cmdcount_by_negative_group"
        else:
            symbol_name = "g_LMAC_HOSTCMD_handlers"
            cmdcount_symbol_name = "g_LMAC_HOSTCMD_cmdcount_by_group"

    table_addr = get_symbol_addr(symbol_name)
    table_data = getDataAt(table_addr)
    print("{}: {} ({} bytes) at {}".format(symbol_name, table_data, table_data.getLength(), table_addr))

    # Set the data type of the main table
    groups_count = table_data.getLength() // 4
    if is_umac:
        umac_hostcmd_entry_t
        set_data_type(
            "hostcmd table",
            table_addr,
            ghidra.program.model.data.ArrayDataType(umac_hostcmd_entry_p_t, groups_count, 4))
    else:
        set_data_type(
            "hostcmd table",
            table_addr,
            ghidra.program.model.data.ArrayDataType(void_pp_t, groups_count, 4))

    # Get the maximum command for each group
    cmdcount_addr = get_symbol_addr(cmdcount_symbol_name)
    print("  Maximum command for each group at {}".format(cmdcount_addr))
    set_data_type(
        "cmd count",
        cmdcount_addr,
        ghidra.program.model.data.ArrayDataType(byte_t, groups_count, 1))

    if is_umac:
        # Load secondary tables
        second_table_addr = get_symbol_addr(second_symbol_name)
        second_cmdcount_addr = get_symbol_addr(second_cmdcount_symbol_name)

    # Iterate on group tables
    for idx_group in range(groups_count):
        group_id = (0xff - idx_group) if is_negative else idx_group
        group_raw_addr = getInt(table_addr.addNoWrap(4 * idx_group))
        # if group_raw_addr == 0:
        #     continue
        group_addr = ram.getAddress(group_raw_addr) if group_raw_addr != 0 else None
        group_cmdcount = getByte(cmdcount_addr.addNoWrap(idx_group)) & 0xff

        if is_umac:
            second_group_cmdcount = getByte(second_cmdcount_addr.addNoWrap(idx_group)) & 0xff
            second_group_raw_addr = getInt(second_table_addr.addNoWrap(4 * idx_group))
            second_group_addr = ram.getAddress(second_group_raw_addr) if second_group_raw_addr != 0 else None
            if group_cmdcount == 0 and second_group_cmdcount == 0:
                continue
        else:
            if group_cmdcount == 0:
                continue

        try:
            group_name, known_cmds = iwl_mvm_command_groups[group_id]
        except KeyError:
            group_name = None
            known_cmds = {}
        if is_umac:
            print("  [0x{:02x}] {} ({} commands, {} secondary) at {} and {}".format(
                group_id, group_name or "?",
                group_cmdcount, second_group_cmdcount,
                group_addr, second_group_addr))
        else:
            print("  [0x{:02x}] {} ({} commands) at {}".format(group_id, group_name or "?", group_cmdcount, group_addr))

        if group_cmdcount != 0:
            if is_umac:
                set_data_type(
                    "group 0x{:02x}".format(group_id),
                    group_addr,
                    ghidra.program.model.data.ArrayDataType(umac_hostcmd_entry_t, group_cmdcount, 6))
            else:
                set_data_type(
                    "group 0x{:02x}".format(group_id),
                    group_addr,
                    ghidra.program.model.data.ArrayDataType(void_p_t, group_cmdcount, 4))

            # Compute the group name
            name_part_1 = "HCMD_UMAC_" if is_umac else "HCMD_LMAC_"

            if not group_name:
                if is_umac and group_id in (9, 0xa):  # In UMAC, groups 9 and 0xa are identical
                    name_part_2 = "09_and_0a_"
                else:
                    name_part_2 = "{:02x}_".format(group_id)
            elif group_id == 1:  # Groups 0 and 1 are identical
                name_part_2 = "00_{}_".format(iwl_mvm_command_groups[0][0])
            else:
                name_part_2 = "{:02x}_{}_".format(group_id, group_name)
            group_tbl_name = name_part_1 + name_part_2 + "handlers"
            current_sym = getSymbolAt(group_addr)
            if not current_sym or current_sym.name != group_tbl_name:
                print("Creating label {!r} at {!r} (was {!r})".format(group_tbl_name, group_addr, current_sym))
                do_create = False
                if str(current_sym) == "PTR_ARRAY_ram_{:08x}".format(group_raw_addr):
                    do_create = True
                else:
                    print("! ERROR: unexpected already-defined label {!r} at {}".format(current_sym, group_addr))
                    do_create = False

                if do_create and UPDATE_DB_REAL:
                    createLabel(group_addr, group_tbl_name, True)  # makePrimary = True

        # Iterate on commands
        for cmd_id in range(group_cmdcount):
            if is_umac:
                cmd_raw_addr = getInt(group_addr.addNoWrap(6 * cmd_id))
                cmd_run_context = getShort(group_addr.addNoWrap(6 * cmd_id + 4))
            else:
                cmd_raw_addr = getInt(group_addr.addNoWrap(4 * cmd_id))
                cmd_run_context = None
            if cmd_raw_addr == 0:
                continue
            cmd_addr = ram.getAddress(cmd_raw_addr)
            cmd_name = known_cmds.get(cmd_id)

            # Compute the function name
            if not cmd_name:
                name_part_3 = "{:02x}".format(cmd_id)
            elif cmd_name.endswith("_CMD"):
                name_part_3 = "{:02x}_{}".format(cmd_id, cmd_name[:-4])
            else:
                name_part_3 = "{:02x}_{}".format(cmd_id, cmd_name)

            fct_name = name_part_1 + name_part_2 + name_part_3

            if cmd_run_context is None:
                desc_runctx = ""
            elif cmd_run_context == 0:
                desc_runctx = " (in MAIN)"
            elif cmd_run_context == 1:
                desc_runctx = " (in BACKGROUND)"
            elif cmd_run_context == 4:
                desc_runctx = " (direct)"
            elif (cmd_run_context & 0xf) == 0:
                second_idx = cmd_run_context >> 4
                second_desc = describe_umac_secondary_index(second_idx)
                desc_runctx = " (in MAIN, + index 0x{:02x}: {})".format(second_idx, second_desc)
            elif (cmd_run_context & 0xf) == 4:
                second_idx = cmd_run_context >> 4
                second_desc = describe_umac_secondary_index(second_idx)
                desc_runctx = " (direct + index 0x{:02x}: {})".format(second_idx, second_desc)
            else:
                desc_runctx = " (unknown run context {:#x})".format(cmd_run_context)

            current_sym = getSymbolAt(cmd_addr)
            print("    [0x{:02x}:0x{:02x}] {:40s} ({:50s}) at {}{}".format(
                group_id, cmd_id, cmd_name or "?", current_sym, cmd_addr, desc_runctx))

            if not current_sym or current_sym.name != fct_name:
                if str(current_sym).startswith(name_part_1) and cmd_name is None:
                    # Skip custom names for unknown commands
                    pass
                elif str(current_sym) == "HCMD_UMAC_transmit_to_LMAC":
                    pass
                elif str(current_sym) == "HCMD_UMAC_notimplemented":
                    pass
                else:
                    print("Creating label {!r} at {!r} (was {!r})".format(fct_name, cmd_addr, current_sym))
                    # Prevent erasing custom symbols
                    do_create = False
                    if str(current_sym) == "DAT_ram_{:08x}".format(cmd_raw_addr):
                        do_create = True
                    elif str(current_sym) == "FUN_ram_{:08x}".format(cmd_raw_addr):
                        do_create = True
                    elif str(current_sym) == "LAB_ram_{:08x}".format(cmd_raw_addr):
                        do_create = True
                    elif str(current_sym) == fct_name + "_CMD":  # Remove _CMD suffix
                        do_create = True
                    elif str(current_sym) == name_part_1 + name_part_2 + "{:02x}".format(cmd_id):  # Define the cmd name
                        do_create = True
                    else:
                        print("! ERROR: unexpected already-defined label {!r} at {}".format(current_sym, cmd_addr))
                        do_create = False

                    if do_create and UPDATE_DB_REAL:
                        createLabel(cmd_addr, fct_name, True)  # makePrimary = True

            # Create function at the given address
            if not getFunctionAt(cmd_addr):
                print("Creating function {!r} (sym {!r}) at {}".format(fct_name, current_sym, cmd_addr))
                if UPDATE_DB_REAL:
                    disassemble(cmd_addr)
                    createFunction(cmd_addr, fct_name)

            # For UMAC, set function type to "void fct_name(HOSTCMD_HANDLER_CONTEXT *ctx)"
            if is_umac:
                cmd_fct = getFunctionAt(cmd_addr)
                current_signature = cmd_fct.getSignature()
                if str(current_signature) != "void stdcall {}(HOSTCMD_HANDLER_CONTEXT * ctx)".format(cmd_fct.getName()):
                    print("Setting function signature of {} at {} (current: {})".format(fct_name, cmd_addr, current_signature))
                    do_create = False
                    if str(current_signature) == "undefined stdcall {}(HOSTCMD_HANDLER_CONTEXT * ctx)".format(cmd_fct.getName()):
                        do_create = True
                    else:
                        print("! ERROR: unexpected function signature {!r} at {}".format(str(current_signature), cmd_addr))
                        print("expected                               {!r}".format("void stdcall {}(HOSTCMD_HANDLER_CONTEXT * ctx)".format(cmd_fct.getName())))
                        do_create = False
                    if do_create and UPDATE_DB_REAL:
                        command = ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                            cmd_addr,
                            umac_hostcmd_handler_t,
                            ghidra.program.model.symbol.SourceType.ANALYSIS)
                        if not runCommand(command):
                            raise RuntimeError("Failed to run ApplyFunctionSignatureCmd")

        if is_umac:
            for inv_cmd_id in range(second_group_cmdcount - 1, -1, -1):
                second_idx = getShort(second_group_addr.addNoWrap(2 * inv_cmd_id))
                if second_idx != 0:
                    cmd_id = 0xff - inv_cmd_id
                    cmd_name = known_cmds.get(cmd_id)
                    second_desc = describe_umac_secondary_index(second_idx)
                    print("    [0x{:02x}:0x{:02x}] {:40s} index 0x{:02x}: {}".format(
                        group_id, cmd_id, cmd_name or "?", second_idx, second_desc))


process_hostcmd_definitions(False, False)
process_hostcmd_definitions(False, True)

if HAVE_UMAC:
    process_hostcmd_definitions(True, False)
    process_hostcmd_definitions(True, True)

    print("g_UMAC_HOSTCMD_secondary_table:")
    for second_idx in range(50):
        second_desc = describe_umac_secondary_index(second_idx)
        print("  <0x{:02x}> {}".format(second_idx, second_desc))
