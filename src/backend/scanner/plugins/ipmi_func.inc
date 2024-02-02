# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# IPMI related functions

global_var IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ, IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP;
global_var IPMI_2_PAYLOAD_RAKP1, IPMI_2_PAYLOAD_RAKP2;

IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ = raw_string(0x10);  # RCMP+ Open Session Request, not encrypted, not authenticated
IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP = raw_string(0x11);  # RCMP+ Open Session Response, not encrypted, not authenticated
IPMI_2_PAYLOAD_RAKP1            = raw_string(0x12);  # Payload Type: RAKP Message 1, not encrypted, not authenticated
IPMI_2_PAYLOAD_RAKP2            = raw_string(0x13);  # Payload Type: RAKP Message 2, not encrypted, not authenticated


# @brief Creates an IPMI v2.0 Open Session Request
#
# @param session_id Session ID to use
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request or NULL in case of an error.
#
function ipmi_v2_create_open_session_request(console_session_id, debug) {
  local_var console_session_id, debug;
  local_var header, data, packet;

  if (!console_session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#console_session_id#-#ipmi_v2_create_open_session_request");
    return NULL;
  }

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x06,                             # Authentication Type: RMCP+
                      IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ,  # Payload Type
                      0x00, 0x00, 0x00, 0x00,           # Session ID
                      0x00, 0x00, 0x00, 0x00);          # Session Sequence Number

  data = raw_string(0x00, 0x00,                         # Maximum Access
                    0x00, 0x00,                         # Reserved
                    mkdword(console_session_id),        # Console Session ID
                    0x00, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00,             # HMAC-SHA1
                    0x02, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00);            # AES Encryption

  packet = header + mkword(strlen(data)) + data;

  if (debug)
    display('IPMI v2.0 Open Session Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Parses the response to an IPMI v2 Open Session Request
#
# @param data Open Session Response to parse
# @debug debug (optional) If TRUE print out debug messages
#
# @return Returns the supplied BMC Session ID or NULL in case of an error while parsing
#
function ipmi_v2_parse_open_session_reply(data, debug) {
  local_var data, debug;
  local_var offset, len, message;
  local_var bmc_session_id;

  if (!data) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ipmi_v2_parse_open_session_reply");
    return NULL;
  }

  if (strlen(data) < 52 || hexstr(data) !~ "^0600ff07")
    return NULL;

  offset = 4; # Skip Remote Management Control Protocol part

  if (data[offset + 1] != IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP)
    return NULL;

  len = getword(blob: data, pos: offset + 10);
  message = substr(data, offset + 12);

  if (debug)
    display('IPMI v2.0 Open Session Response Message:\n' + hexdump(ddata: message));

  # nb: Check for RMCP Error code
  if (hexstr(message[1]) != "00")
    return NULL;

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  bmc_session_id = getdword(blob: message, pos: 8);

  return bmc_session_id;
}

# @brief Creates a IPMI v2.0 RAKP Message 1
#
# @param bmc_session_id BMC Session ID probided by the server
# @param username Username to create the message for
# @param console_id (optional, otherwise a random one will be created) Console ID (16 bytes)
# @param debug (optional) If TRUE print out debug messages
#
# @ return The created RAKP Message 1 packet or NULL in case of an error
#
function ipmi_v2_create_rakp_message_1(bmc_session_id, console_id, username, debug) {
  local_var bmc_session_id, username, console_id, debug;
  local_var header, data, packet;

  if (!bmc_session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#bmc_session_id#-#ipmi_v2_create_rakp_message_1");
    return NULL;
  }

  if (!username)
    username = "";

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x06,                             # Authentication Type: RMCP+
                      IPMI_2_PAYLOAD_RAKP1,             # Payload Type
                      0x00, 0x00, 0x00, 0x00,           # Session ID
                      0x00, 0x00, 0x00, 0x00);          # Session Sequence Number

  if (!console_id) {
    data = raw_string(0x00, 0x00, 0x00, 0x00,
                      mkdword(bmc_session_id),            # BMC Session ID
                      mkdword(rand()),                    # Console ID
                      mkdword(rand()),
                      mkdword(rand()),
                      mkdword(rand()),
                      0x14, 0x00, 0x00,
                      mkbyte(strlen(username)),           # Username length
                      username);                          # Username
  } else {
    if (strlen(console_id) != 16) {
      set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v2_create_rakp_message_1(): console_id has wrong length");
      return NULL;
    }

    data = raw_string(0x00, 0x00, 0x00, 0x00,
                      mkdword(bmc_session_id),            # BMC Session ID
                      console_id,                         # Console ID
                      0x14, 0x00, 0x00,
                      mkbyte(strlen(username)),           # Username length
                      username);
  }

  packet = header + mkword(strlen(data)) + data;

  if (debug)
    display('IPMI v2.0 Create RAKP Message 1 Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Parses the response to an IPMI v2 RAKP Request
#
# @param data RAKP Response to parse
# @debug debug (optional) If TRUE print out debug messages
#
# @return An array containing the extracted information or NULL in case of an error
#
#         ret_array["hash"]        = SHA1 Hash sent by the server
#         ret_array["bmc_guid"]    = BMC GUID
#         ret_array["rand_bmc_id"] = BMC ID sent by the server
#
function ipmi_v2_parse_rakp_message_reply(data, debug) {
  local_var data, debug;
  local_var offset, len, message, hash, bmc_guid, rand_bmc_id;
  local_var res;

  res = make_array();

  if (!data) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ipmi_v2_parse_rakp_message_reply");
    return NULL;
  }

  # nb: Response seems to not included a valid hash or is not an IPMI response
  if (strlen(data) < 76 || hexstr(data) !~ "^0600ff07")
    return NULL;

  offset = 4; # Skip Remote Management Control Protocol part

  if (data[offset + 1] != IPMI_2_PAYLOAD_RAKP2)
    return NULL;

  len = getword(blob: data, pos: offset + 10);
  message = substr(data, offset + 12);

  if (debug)
    display('IPMI v2.0 RAKP2 Response Message:\n' + hexdump(ddata: message));

  # nb: Check for RMCP Error code
  if (hexstr(message[1]) != "00")
    return NULL;

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  hash = substr(message, 40);

  if (hexstr(hash) == "0000000000000000000000000000000000000000")
    return NULL;

  bmc_guid = substr(message, 24, 39);
  rand_bmc_id = substr(message, 8, 23);

  res["hash"] = hash;
  res["bmc_guid"] = bmc_guid;
  res["rand_bmc_id"] = rand_bmc_id;

  return res;
}
