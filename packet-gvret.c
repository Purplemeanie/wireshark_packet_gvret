/* packet-gvret.c
 *
 * Wireshark - Network traffic analyzer
 *
 * GVRET Binary Protocol dissector (ESP32RET / SavvyCAN style)
 * Transport: TCP stream
 *
 * CMD 0x00: CAN frame
 *   F1 00
 *   ts (u32 LE micros)
 *   id (u32 LE, bit31 indicates extended in ESP32RET)
 *   lenbus (u8: low nibble DLC, high nibble bus)
 *   data[dlc]
 *   checksum (u8, currently 0x00 in ESP32RET)
 *
 * CMD 0x09: keepalive
 *   F1 09 DE AD
 *
 * Upper-layer dispatch:
 *   We convert GVRET frames into SocketCAN-style metadata (can_info_t)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-socketcan.h>
#include <stdbool.h>

#define GVRET_START_MARKER 0xF1
#define GVRET_CMD_CAN      0x00
#define GVRET_CMD_KEEPALIVE 0x09

static int proto_gvret = -1;

/* Preferences */
static guint pref_tcp_port = 23;

/* Header fields */
static int hf_gvret_start = -1;
static int hf_gvret_cmd   = -1;

static int hf_gvret_ts    = -1;

static int hf_gvret_id_raw = -1;
static int hf_gvret_id     = -1;
static int hf_gvret_ext    = -1;

static int hf_gvret_lenbus = -1;
static int hf_gvret_dlc    = -1;
static int hf_gvret_bus    = -1;

static int hf_gvret_data   = -1;
static int hf_gvret_cksum  = -1;

static int hf_gvret_keep_magic = -1;

/* Expert info */
static expert_field ei_gvret_desync = EI_INIT;

/* Subtrees */
static gint ett_gvret = -1;
static gint ett_gvret_can = -1;
static gint ett_gvret_keep = -1;

static dissector_handle_t gvret_handle;

static dissector_handle_t gvret_can_entry_handle = NULL;

/* Preference: when dispatching, try heuristics before Decode-As table matches */
static bool pref_use_heuristics_first = true;

static dissector_table_t can_subdissector_table = NULL;

static const value_string gvret_cmd_vals[] = {
    { GVRET_CMD_CAN,       "CAN Frame" },
    { GVRET_CMD_KEEPALIVE, "Keep Alive" },
    { 0, NULL }
};

static guint
gvret_get_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    const gint remaining = tvb_reported_length_remaining(tvb, offset);
    if (remaining < 2) {
        return 0; /* ask for more */
    }

    const guint8 start = tvb_get_uint8(tvb, offset);
    if (start != GVRET_START_MARKER) {
        /* tcp_dissect_pdus assumes the PDU starts at offset; we sync before calling it. */
        return 0;
    }

    const guint8 cmd = tvb_get_uint8(tvb, offset + 1);

    if (cmd == GVRET_CMD_CAN) {
        /* Need at least through lenbus to know DLC: 11 bytes */
        if (remaining < 11) {
            return 0;
        }
        const guint8 lenbus = tvb_get_uint8(tvb, offset + 10);
        const guint8 dlc = (guint8)(lenbus & 0x0F);
        return (guint)(12 + dlc); /* includes checksum byte */
    }

    if (cmd == GVRET_CMD_KEEPALIVE) {
        return 4;
    }

    /* Unknown cmd:
     * We cannot determine length safely without a delimiter, so treat the rest of
     * this TCP segment as "raw" and avoid desegmentation for unknown commands.
     * (You can extend this later for other GVRET cmd types.)
     */
    return (guint)remaining;
}

static int
gvret_dissect_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    const gint tvblen = tvb_captured_length(tvb);
    if (tvblen < 2) {
        return tvblen;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GVRET");

    const guint8 start = tvb_get_uint8(tvb, 0);
    const guint8 cmd   = tvb_get_uint8(tvb, 1);

    if (start != GVRET_START_MARKER) {
        /* If we ever get here, show a minimal node */
        proto_item *ti_bad = proto_tree_add_item(tree, proto_gvret, tvb, 0, -1, ENC_NA);
        expert_add_info(pinfo, ti_bad, &ei_gvret_desync);
        return tvblen;
    }

    /* ---- CAN: build ONE node (no outer + no inner “CAN Frame”) ---- */
    if (cmd == GVRET_CMD_CAN) {
        if (tvblen < 11) {
            return tvblen;
        }

        const guint32 ts    = tvb_get_letohl(tvb, 2);
        const guint32 idraw = tvb_get_letohl(tvb, 6);
        const guint8  lenbus = tvb_get_uint8(tvb, 10);
        const guint8  dlc = (guint8)(lenbus & 0x0F);
        const guint8  bus = (guint8)((lenbus >> 4) & 0x0F);

        const gint needed = 12 + dlc;
        if (tvblen < needed) {
            return tvblen;
        }

        const gboolean is_ext = (idraw & 0x80000000U) != 0;

        guint32 can_id_display;
        guint32 can_id_socketcan;

        if (is_ext) {
            can_id_display   = (idraw & 0x1FFFFFFFU);
            can_id_socketcan = (can_id_display | CAN_EFF_FLAG);
        } else {
            can_id_display   = (idraw & CAN_SFF_MASK);
            can_id_socketcan = can_id_display;
        }

        proto_item *ti_pdu = proto_tree_add_item(tree, proto_gvret, tvb, 0, needed, ENC_NA);
        proto_item_set_text(ti_pdu,
            "CAN%u %s ID=0x%X DLC=%u TS=%u",
            bus, is_ext ? "EXT" : "STD", can_id_display, dlc, ts);

        proto_tree *pdu_tree = proto_item_add_subtree(ti_pdu, ett_gvret_can);

        proto_tree_add_item(pdu_tree, hf_gvret_start,  tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pdu_tree, hf_gvret_cmd,    tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pdu_tree, hf_gvret_ts,     tvb, 2, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(pdu_tree, hf_gvret_id_raw, tvb, 6, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_boolean(pdu_tree, hf_gvret_ext, tvb, 6, 4, is_ext);
        proto_tree_add_uint(pdu_tree, hf_gvret_id,     tvb, 6, 4, can_id_display);

        proto_tree_add_item(pdu_tree, hf_gvret_lenbus, tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_uint(pdu_tree, hf_gvret_dlc,    tvb, 10, 1, dlc);
        proto_tree_add_uint(pdu_tree, hf_gvret_bus,    tvb, 10, 1, bus);

        if (dlc > 0) {
            proto_tree_add_item(pdu_tree, hf_gvret_data, tvb, 11, dlc, ENC_NA);
        }
        proto_tree_add_item(pdu_tree, hf_gvret_cksum, tvb, 11 + dlc, 1, ENC_BIG_ENDIAN);

        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "CAN%u %s ID=0x%X DLC=%u TS=%u",
                     bus, is_ext ? "EXT" : "STD", can_id_display, dlc, ts);


        /* --- 1) Create CAN layer node using can-hostendian --- */
        guint8 dlc8 = dlc > 8 ? 8 : dlc;

        guint8 *cf = (guint8 *)g_malloc0(16);
        const guint32 can_id_wire = can_id_socketcan;   /* includes CAN_EFF_FLAG if ext */

        /* host-endian on Apple Silicon == little-endian */
        cf[0] = (guint8)(can_id_wire & 0xFF);
        cf[1] = (guint8)((can_id_wire >> 8) & 0xFF);
        cf[2] = (guint8)((can_id_wire >> 16) & 0xFF);
        cf[3] = (guint8)((can_id_wire >> 24) & 0xFF);
        cf[4] = dlc8;

        if (dlc8 > 0) {
            tvb_memcpy(tvb, cf + 8, 11, dlc8);
        }

        tvbuff_t *can_tvb = tvb_new_real_data(cf, 16, 16);
        tvb_set_free_cb(can_tvb, g_free);
        add_new_data_source(pinfo, can_tvb, "Reassembled CAN frame");

        if (gvret_can_entry_handle) {
            call_dissector(gvret_can_entry_handle, can_tvb, pinfo, pdu_tree);
        } else {
            proto_tree_add_expert_format(pdu_tree, pinfo, &ei_gvret_desync,
                                        tvb, 0, 0, "No CAN dissector handle found (can-hostendian/can-bigendian)");
        }


        /* Dispatch payload for ISO-TP/J1939/etc */
        if (can_subdissector_table) {
            tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, 11, dlc8);

            can_info_t can_info;
            memset(&can_info, 0, sizeof(can_info));
            can_info.id     = can_id_socketcan;     /* includes CAN_EFF_FLAG if ext */
            can_info.len    = dlc8;
            can_info.fd     = CAN_TYPE_CAN_CLASSIC;
            can_info.bus_id = bus;

            dissector_try_payload_with_data(can_subdissector_table,
                                            payload_tvb,
                                            pinfo,
                                            pdu_tree,
                                            pref_use_heuristics_first,
                                            &can_info);
        }

        return needed; 
    }

    /* ---- Non-CAN commands: fall back to the “outer” generic node ---- */
    proto_item *ti = proto_tree_add_item(tree, proto_gvret, tvb, 0, -1, ENC_NA);
    proto_tree *gvret_tree = proto_item_add_subtree(ti, ett_gvret);

    proto_tree_add_item(gvret_tree, hf_gvret_start, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(gvret_tree, hf_gvret_cmd,   tvb, 1, 1, ENC_BIG_ENDIAN);

    if (cmd == GVRET_CMD_KEEPALIVE) {
        proto_item_set_text(ti, "GVRET Keep Alive");
        proto_tree_add_item(gvret_tree, hf_gvret_keep_magic, tvb, 2, 2, ENC_BIG_ENDIAN);
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_str(pinfo->cinfo, COL_INFO, "Keep Alive");
        return 4;
    }

    /* Unknown cmd: show raw payload */
    proto_item_set_text(ti, "GVRET CMD=0x%02X (undecoded)", cmd);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "CMD=0x%02X (undecoded)", cmd);

    if (tvblen > 2) {
        proto_tree_add_item(gvret_tree, hf_gvret_data, tvb, 2, tvblen - 2, ENC_NA);
    }

    return tvblen;
}

static int
dissect_gvret(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* TCP stream may begin mid-frame — sync to 0xF1 marker */
    const gint len = tvb_reported_length(tvb);
    gint f1pos = tvb_find_uint8(tvb, 0, len, GVRET_START_MARKER);

    if (f1pos < 0) {
        /* No start marker found in this segment */
        return 0;
    }

    /* If we skipped bytes before the first marker, show expert info */
    if (f1pos > 0 && tree) {
        proto_item *ti_skip =
            proto_tree_add_item(tree, proto_gvret, tvb, 0, f1pos, ENC_NA);
        expert_add_info(pinfo, ti_skip, &ei_gvret_desync);
    }

    /* Create a subset starting at the marker */
    tvbuff_t *tvb_sync = tvb_new_subset_remaining(tvb, f1pos);

    proto_tree *gvret_root_tree = NULL;

    if (tree) {
        proto_item *ti_root =
            proto_tree_add_item(tree, proto_gvret, tvb_sync, 0, -1, ENC_NA);
        proto_item_set_text(ti_root, "GVRET");
        gvret_root_tree = proto_item_add_subtree(ti_root, ett_gvret);
    }

    tcp_dissect_pdus(tvb_sync, pinfo,
                     gvret_root_tree ? gvret_root_tree : tree,
                     true,            /* desegment */
                     2,               /* minimum header length (F1 + cmd) */
                     gvret_get_pdu_len,
                     gvret_dissect_pdu,
                     data);

    return tvb_captured_length(tvb);
}

void
proto_register_gvret(void)
{
    static hf_register_info hf[] = {
        { &hf_gvret_start,
          { "Start", "gvret.start", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_cmd,
          { "Command", "gvret.cmd", FT_UINT8, BASE_HEX, VALS(gvret_cmd_vals), 0x0, NULL, HFILL }},

        { &hf_gvret_ts,
          { "Timestamp (us)", "gvret.ts", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_id_raw,
          { "CAN ID (raw)", "gvret.can.id_raw", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_ext,
          { "Extended ID", "gvret.can.ext", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_id,
          { "CAN ID", "gvret.can.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_lenbus,
          { "Len+Bus (packed)", "gvret.can.lenbus", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_dlc,
          { "DLC", "gvret.can.dlc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_bus,
          { "Bus", "gvret.can.bus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_data,
          { "Data", "gvret.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_cksum,
          { "Checksum", "gvret.cksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_gvret_keep_magic,
          { "Keep Alive Magic", "gvret.keep.magic", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_gvret,
        &ett_gvret_can,
        &ett_gvret_keep
    };

    static ei_register_info ei[] = {
        { &ei_gvret_desync,
          { "gvret.desync", PI_SEQUENCE, PI_NOTE,
            "Bytes skipped before GVRET start marker (stream desync)", EXPFILL }}
    };

    expert_module_t *expert_gvret;

    proto_gvret = proto_register_protocol(
        "GVRET Binary Protocol (ESP32RET)",
        "GVRET",
        "gvret"
    );

    proto_register_field_array(proto_gvret, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_gvret = expert_register_protocol(proto_gvret);
    expert_register_field_array(expert_gvret, ei, array_length(ei));

    /* Preferences */
    module_t *gvret_module = prefs_register_protocol(proto_gvret, NULL);

    prefs_register_uint_preference(gvret_module, "tcp.port",
        "GVRET TCP port",
        "TCP port for GVRET binary stream",
        10, &pref_tcp_port);


    prefs_register_bool_preference(gvret_module, "use_heuristics_first",
        "Try heuristic CAN subdissectors first",
        "When calling SocketCAN subdissectors, try heuristic dissectors before Decode-As table matches",
        &pref_use_heuristics_first);
}

void
proto_reg_handoff_gvret(void)
{
    static gboolean initialized = FALSE;
    static guint saved_port = 0;

    if (!initialized) {
        gvret_handle = create_dissector_handle(dissect_gvret, proto_gvret);
        initialized = TRUE;
    } else if (saved_port != 0 && saved_port != pref_tcp_port) {
        dissector_delete_uint("tcp.port", saved_port, gvret_handle);
    }

    /* Choose CAN dissector variant based on host endianness */
    if (!gvret_can_entry_handle) {
#if G_BYTE_ORDER == G_BIG_ENDIAN
        gvret_can_entry_handle = find_dissector("can-bigendian");
#else
        gvret_can_entry_handle = find_dissector("can-hostendian");
#endif
        if (!gvret_can_entry_handle) {
            gvret_can_entry_handle = find_dissector("can-hostendian");
            if (!gvret_can_entry_handle)
                gvret_can_entry_handle = find_dissector("can-bigendian");
        }
    }

    if (!can_subdissector_table) {
        can_subdissector_table = find_dissector_table("can.subdissector");
    }

    dissector_add_uint("tcp.port", pref_tcp_port, gvret_handle);
    saved_port = pref_tcp_port;
}