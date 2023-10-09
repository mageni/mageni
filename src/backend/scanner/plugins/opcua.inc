# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Sends a OpenSecureChannelRequest to the server and returns the received data (e.g.
#        OpenSecureChannelResponse)
#
# @note The function currently returns all received data and doesn't check the response for any
#       error or similar.
#
# @param socket The already opened UDP or TCP socket to the remote host.
#
# @return The received OpenSecureChannelResponse or NULL if no data was received or no socket was
#         passed.
#
function opcua_open_secure_channel_req_res(socket) {

  local_var socket;
  local_var opc_req_header, opc_req_footer, l, len, opc_req, recv;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#opcua_open_secure_channel_req_res");
    return NULL;
  }

  opc_req_header = raw_string("OPN",                                                 # Message Type
                              "F");                                                  # Chunk Type

  opc_req_footer = raw_string(0x00, 0x00, 0x00, 0x00,                                # SecureChannelId
                              0x2f, 0x00, 0x00, 0x00,                                #
                              "http://opcfoundation.org/UA/SecurityPolicy#None",     # SecurityPolicyUri
                              0xff, 0xff, 0xff, 0xff,                                # SenderCertificate (Missing)
                              0xff, 0xff, 0xff, 0xff,                                # ReceiverCertificateThumbprint (Missing)
                              0x01, 0x00, 0x00, 0x00,                                # SequenceNumber
                              0x01, 0x00, 0x00, 0x00,                                # RequestId
                              0x01, 0x00, 0xbe, 0x01,                                # ExpandedNodeId (OpenSecureChannelRequest)
                              0x00, 0x00,                                            # Authentication Token
                              0x00, 0x00, 0x00, 0x00,                                # Timestamp
                              0x00, 0x00, 0x00, 0x00,                                # Timestamp2
                              0x01, 0x00, 0x00, 0x00,                                # RequestHandle
                              0x00, 0x00, 0x00, 0x00,                                # Return Diagnostics
                              0xff, 0xff, 0xff, 0xff,                                # AuditEntryId
                              0xe8, 0x03, 0x00, 0x00,                                # TimeoutHint
                              0x00, 0x00, 0x00,                                      # AdditionalHeader
                              0x00, 0x00, 0x00, 0x00,                                # ClientProtocolVersion 0
                              0x00, 0x00, 0x00, 0x00,                                # SecurityTokenRequestType (Issue)
                              0x01, 0x00, 0x00, 0x00,                                # MessageSecurityMode (None)
                              0x00, 0x00, 0x00, 0x00,                                # ClientNonce (Missing)
                              0x80, 0xee, 0x36, 0x00);                               # RequestedLifetime (3600000)

  l = (strlen(opc_req_header) + strlen(opc_req_footer) + 4);
  len = mkdword(l);

  opc_req = opc_req_header + len + opc_req_footer;
  send(socket: socket, data: opc_req);
  recv = recv(socket: socket, length: 512);

  return recv;
}

# @brief Sends a CreateSessionRequest to the server, parses the CreateSessionResponse for errors and
#        returns the received AuthenticationToken byte string.
#
# @param socket       The already opened UDP or TCP socket to the remote host.
#
# @param channel_id   The SecureChannelId to send to the target.
#
# @param endpoint_url The EndpointUrl to send to the target.
#
# @param timestamp    The Timestamp to send to the target.
#
# @return Returns the received AuthenticationToken byte string if successfully extracted, FALSE
#         otherwise and NULL if not all mandatory parameters have been given.
#
function opcua_create_session_req_res(socket, channel_id, endpoint_url, timestamp) {

  local_var socket, channel_id, endpoint_url, timestamp;
  local_var epu_len, opc_req_header, opc_req_footer, l, len, opc_req;
  local_var recv, recv_len, result, sessid_len, pos, authtoken_len, authToken;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#opcua_create_session_req_res");
    return NULL;
  }

  if (isnull(channel_id)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#channel_id#-#opcua_create_session_req_res");
    return NULL;
  }

  if (isnull(endpoint_url)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#endpoint_url#-#opcua_create_session_req_res");
    return NULL;
  }

  if (isnull(timestamp)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#timestamp#-#opcua_create_session_req_res");
    return NULL;
  }

  epu_len = mkdword(strlen(endpoint_url));

  opc_req_header = raw_string("MSG",                      # Message Type
                              "F");                       # Chunk Type

  opc_req_footer = raw_string(channel_id,                 # SecureChannelId
                              0x01, 0x00, 0x00, 0x00,     # Security Token Id
                              0x02, 0x00, 0x00, 0x00,     # Security Sequence Number
                              0x02, 0x00, 0x00, 0x00,     # Security RequestId
                              0x01, 0x00, 0xcd, 0x01,     # ExpandedNodeId (with CreateSessionRequest (461))
                              0x00, 0x00,                 # AuthenticationToken
                              timestamp,                  # Timestamp
                              0x02, 0x00, 0x00, 0x00,     # RequestHandle
                              0x00, 0x00, 0x00, 0x00,     # ReturnDiagnostics
                              0xff, 0xff, 0xff, 0xff,     # AuditEntryId
                              0xe8, 0x03, 0x00, 0x00,     # Timeout (1000)
                              0x00, 0x00, 0x00,           # AdditionalHeader
                              0x14, 0x00, 0x00, 0x00,     # ClientDescription
                              0x75, 0x72, 0x6e, 0x3a,     # urn:freeopcua:client
                              0x66, 0x72, 0x65, 0x65,
                              0x6f, 0x70, 0x63, 0x75,
                              0x61, 0x3a, 0x63, 0x6c,
                              0x69, 0x65, 0x6e, 0x74,
                              0x1e, 0x00, 0x00, 0x00,     # maybe string limiter?
                              0x75, 0x72, 0x6e, 0x3a,     # ProductUri (urn:freeopcua.github.io:client)
                              0x66, 0x72, 0x65, 0x65,
                              0x6f, 0x70, 0x63, 0x75,
                              0x61, 0x2e, 0x67, 0x69,
                              0x74, 0x68, 0x75, 0x62,
                              0x2e, 0x69, 0x6f, 0x3a,
                              0x63, 0x6c, 0x69, 0x65,
                              0x6e, 0x74,
                              0x02, 0x12, 0x00, 0x00,     # ApplicationName
                              0x00, 0x50, 0x75, 0x72,
                              0x65, 0x20, 0x50, 0x79,
                              0x74, 0x68, 0x6f, 0x6e,
                              0x20, 0x43, 0x6c, 0x69,
                              0x65, 0x6e, 0x74,
                              0x01, 0x00, 0x00, 0x00,     # ApplicationType (Client)
                              0xff, 0xff, 0xff, 0xff,     # GatewayServerUri
                              0xff, 0xff, 0xff, 0xff,     # DiscoveryProfileUri
                              0x00, 0x00, 0x00, 0x00,     # DiscoveryUrls
                              0xff, 0xff, 0xff, 0xff,     # ServerUri
                              epu_len,                    # Length of EndpointUrl
                              endpoint_url,               # EndpointUrl
                              0x1b, 0x00, 0x00, 0x00,
                              0x50, 0x75, 0x72, 0x65,     # SessionName
                              0x20, 0x50, 0x79, 0x74,
                              0x68, 0x6f, 0x6e, 0x20,
                              0x43, 0x6c, 0x69, 0x65,
                              0x6e, 0x74, 0x20, 0x53,
                              0x65, 0x73, 0x73, 0x69,
                              0x6f, 0x6e, 0x31,
                              0x20, 0x00, 0x00, 0x00,
                              0xc8, 0x5b, 0x29, 0x74,     # ClientNonce
                              0x4a, 0x25, 0xac, 0xc7,
                              0x28, 0x6a, 0xe5, 0xcf,
                              0x76, 0xa8, 0xd1, 0x82,
                              0xbc, 0x55, 0xe4, 0x88,
                              0x1d, 0x26, 0xf6, 0xe9,
                              0x9a, 0x6c, 0x25, 0x9a,
                              0x26, 0x95, 0x89, 0xa6,
                              0xff, 0xff, 0xff, 0xff,     # ClientCertificate
                              0x00, 0x00, 0x00, 0x00,     # RequestedSessionTimeout
                              0x40, 0x77, 0x4b, 0x41,
                              0x00, 0x00, 0x00, 0x00);    # MaxResponseMessageSize

  l = (strlen(opc_req_header) + strlen(opc_req_footer) + 4);
  len = mkdword(l);
  opc_req = opc_req_header + len + opc_req_footer;

  send(socket: socket, data: opc_req);
  recv = recv(socket: socket, length: 8);
  if (!recv || strlen(recv) < 4)
    return FALSE;

  recv_len = getword(blob: recv, pos: 4);
  if (!recv_len || recv_len < 69)
    return FALSE;

  recv = recv(socket: socket, length: recv_len);

  result = hexstr(substr(recv, 33, 36));
  if (result != "00000000")
    return FALSE;

  # SessionID and AuthenticationToken might differ in length so we have to account that before
  # reading the authentication token
  sessid_len = ord(recv[44]);

  if (sessid_len == 1)
    pos = 48;
  else if (sessid_len == 2)
    pos = 51;
  else if (sessid_len == 4)
    pos = 63;

  authtoken_len = ord(recv[pos]);

  if (authtoken_len == 4)
    authToken = substr(recv, pos, pos + 18);
  else if (authtoken_len == 1)
    authToken = substr(recv, pos, pos + 3);
  else if (authtoken_len == 2)
    authToken = substr(recv, pos, pos + 6);
  else if (authtoken_len == 5)
    authToken = substr(recv, pos, pos + 38);
  else
    return FALSE;

  return authToken;
}

# @brief Sends a ActivateSessionRequest to the server, parses the ActivateSessionResponse for errors
#        and returns the received data.
#
# @param socket     The already opened UDP or TCP socket to the remote host.
#
# @param channel_id The SecureChannelId to send to the target.
#
# @param auth_token The AuthenticationToken extracted via @ref opcua_create_session_req_res.
#
# @param timestamp  The Timestamp to send to the target.
#
# @return The received data if no error happened, FALSE otherwise and NULL if not all mandatory
#         parameters have been given.
#
function opcua_activate_session_req_res(socket, channel_id, auth_token, timestamp) {

  local_var socket, channel_id, auth_token, timestamp;
  local_var opc_req_header, opc_req_footer, l, len, opc_req, recv, result;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#opcua_activate_session_req_res");
    return NULL;
  }

  if (isnull(channel_id)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#channel_id#-#opcua_activate_session_req_res");
    return NULL;
  }

  if (isnull(auth_token)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_token#-#opcua_activate_session_req_res");
    return NULL;
  }

  if (isnull(timestamp)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#timestamp#-#opcua_activate_session_req_res");
    return NULL;
  }

  opc_req_header = raw_string("MSG",                                           # Message Type
                              "F");                                            # Chunk Type

  opc_req_footer = raw_string(channel_id,                                      # SecureChannelId
                              0x01, 0x00, 0x00, 0x00,                          # Security Token Id
                              0x03, 0x00, 0x00, 0x00,                          # Security Sequence Number
                              0x03, 0x00, 0x00, 0x00,                          # Security RequestId
                              0x01, 0x00, 0xd3, 0x01,                          # ExpandedNodeId (with ActivateSessionRequest (467))
                              auth_token,                                      # AuthenticationToken
                              timestamp,                                       # Timestamp
                              0x03, 0x00, 0x00, 0x00,                          # RequestHandle
                              0x00, 0x00, 0x00, 0x00,                          # ReturnDiagnostics
                              0xff, 0xff, 0xff, 0xff,                          # AuditEntryId
                              0xe8, 0x03, 0x00, 0x00,                          # Timeout (1000)
                              0x00, 0x00, 0x00,                                # AdditionalHeader
                              0x2a, 0x00, 0x00, 0x00,                          # Client Signature
                              "http://www.w3.org/2000/09/xmldsig#rsa-sha1",    # Algorithm
                              0x00, 0x00, 0x00, 0x00,                          # Signature
                              0x00, 0x00, 0x00, 0x00,                          # ClientSoftwareCertificates
                              0x01, 0x00, 0x00, 0x00,                          # LocaleIds
                              0x02, 0x00, 0x00, 0x00,
                              0x65, 0x6e,
                              0x01, 0x00, 0x41, 0x01,                          # UserIdentityToken (Anonymous)
                              0x01, 0x0d, 0x00, 0x00,
                              0x00, 0x09, 0x00, 0x00,
                              0x00, 0x41, 0x6e, 0x6f,
                              0x6e, 0x79, 0x6d, 0x6f,
                              0x75, 0x73,
                              0xff, 0xff, 0xff, 0xff,                          # UserTokenSignature
                              0xff, 0xff, 0xff, 0xff);

  l = (strlen(opc_req_header) + strlen(opc_req_footer) + 4);
  len = mkdword(l);
  opc_req = opc_req_header + len + opc_req_footer;

  send(socket: socket, data: opc_req);
  recv = recv(socket: socket, length: 512);
  if (strlen(recv) < 43)
    return FALSE;

  result = hexstr(substr(recv, 40, 43));
  if (result != "00000000")
    return FALSE;

  return TRUE;
}

# @brief Sends a ReadRequest to the server, parses the ReadResponse for errors and returns the
#        received data.
#
# @param socket     The already opened UDP or TCP socket to the remote host.
#
# @param channel_id The SecureChannelId to send to the target.
#
# @param auth_token The AuthenticationToken extracted via @ref opcua_create_session_req_res.
#
# @param timestamp  The Timestamp to send to the target.
#
# @return The received data if no error happened, FALSE otherwise and NULL if not all mandatory
#         parameters have been given.
#
function opcua_read_req_res(socket, channel_id, auth_token, timestamp) {

  local_var socket, channel_id, auth_token, timestamp;
  local_var opc_req_header, opc_req_footer, l, len, opc_req, recv, result;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#opcua_read_req_res");
    return NULL;
  }

  if (isnull(channel_id)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#channel_id#-#opcua_read_req_res");
    return NULL;
  }

  if (isnull(auth_token)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_token#-#opcua_read_req_res");
    return NULL;
  }

  if (isnull(timestamp)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#timestamp#-#opcua_read_req_res");
    return NULL;
  }

  opc_req_header = raw_string("MSG",                                 # Message Type
                              "F");                                  # Chunk Type

  opc_req_footer = raw_string(channel_id,                            # SecureChannelId
                              0x01, 0x00, 0x00, 0x00,                # Security Token Id
                              0x04, 0x00, 0x00, 0x00,                # Security Sequence Number
                              0x04, 0x00, 0x00, 0x00,                # Security RequestId
                              0x01, 0x00, 0x77, 0x02,                # ExpandedNodeId (with ReadRequest (631))
                              auth_token,                            # AuthenticationToken
                              timestamp,                             # Timestamp
                              0x04, 0x00, 0x00, 0x00,                # RequestHandle
                              0x00, 0x00, 0x00, 0x00,                # ReturnDiagnostics
                              0xff, 0xff, 0xff, 0xff,                # AuditEntryId
                              0xe8, 0x03, 0x00, 0x00,                # Timeout (1000)
                              0x00, 0x00, 0x00,                      # AdditionalHeader
                              0x00, 0x00, 0x00, 0x00,                # MaxAge 0
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,                # TimestampsToReturn
                              0x01, 0x00, 0x00, 0x00,                # NodesToRead: ArraySize
                              0x02, 0x00, 0x00,                      # NodeId:
                              0xd0, 0x08, 0x00, 0x00,                # 2256 (ServerStatus)
                              0x0d, 0x00, 0x00, 0x00,                # AttributeId
                              0xff, 0xff, 0xff, 0xff,                # IndexRange
                              0x00, 0x00, 0xff, 0xff, 0xff, 0xff     # DataEncoding
                              );

  l = (strlen(opc_req_header) + strlen(opc_req_footer) + 4);
  len = mkdword(l);
  opc_req = opc_req_header + len + opc_req_footer;

  send(socket: socket, data: opc_req);
  recv = recv(socket: socket, length: 1024);

  if (strlen(recv) < 43)
    return FALSE;

  result = hexstr(substr(recv, 40, 43));
  if (result != "00000000")
    return FALSE;

  return recv;
}

# @brief Tries to read various info like e.g. "Product Name", "Manufacturer" from the remote
#        service, stores the gathered info in the internal knowledge base (KB) and returns a report
#        about the gathered info.
#
# @note Internally the function is calling additional functions like e.g. @ref opcua_read_req_res,
#       @ref opcua_open_secure_channel_req_res, @ref opcua_create_session_req_res or
#       @ref opcua_activate_session_req_res
#
# @param socket       The already opened UDP or TCP socket to the remote host.
#
# @param proto        The protocol to use for the connection (either "udp" or "tcp").
#
# @param port         The port of the connection to the remote host.
#
# @param endpoint_url The EndpointUrl to send to the target.
#
# @return The gathered info in form as a structured report (as a string) or NULL otherwise.
#
function opcua_gather_device_info(socket, proto, port, endpoint_url) {

  local_var socket, proto, port, endpoint_url;
  local_var data, result, timestamp, sec_channel_id, auth_token, len, pos;
  local_var product_uri, manufacturer, product_name, sw_version, report, build;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#opcua_gather_device_info");
    return;
  }

  if (!proto) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#proto#-#opcua_gather_device_info");
    return;
  }

  if (!port) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#port#-#opcua_gather_device_info");
    return;
  }

  if (proto != "udp" && proto != "tcp") {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#opcua_gather_device_info: Unsupported '" + proto + "' passed to proto function parameter. Currently supported: 'udp' or 'tcp'.");
    return;
  }

  if (!endpoint_url) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#endpoint_url#-#opcua_gather_device_info");
    return;
  }

  if (data = opcua_open_secure_channel_req_res(socket: socket)) {
    if (strlen(data) < 122)
      return;

    result = hexstr(substr(data, 119, 122));
    if (result != "00000000")
      return;

    timestamp = substr(data, 107, 114);

    sec_channel_id = substr(data, 32, 35);

    if (auth_token = opcua_create_session_req_res(socket: socket, channel_id: sec_channel_id, endpoint_url: endpoint_url,
                                                  timestamp: timestamp)) {

      if (opcua_activate_session_req_res(socket: socket, channel_id: sec_channel_id, auth_token: auth_token, timestamp: timestamp)) {

        if (data = opcua_read_req_res(socket: socket, channel_id: sec_channel_id, auth_token: auth_token, timestamp: timestamp)) {
          len = getword(blob: data, pos: 87);
          pos = 91;
          product_uri = substr(data, pos, pos + len - 1);

          pos += len;
          len = getword(blob: data, pos: pos);
          pos += 4;
          manufacturer = substr(data, pos, pos + len - 1);
          set_kb_item(name: "opcua/" + port + "/" + proto + "/manufacturer", value: manufacturer);

          pos += len;
          len = getword(blob: data, pos: pos);
          pos += 4;
          product_name = substr(data, pos, pos + len - 1);
          set_kb_item(name: "opcua/" + port + "/" + proto + "/product_name", value: product_name);

          pos += len;
          len = getword(blob: data, pos: pos);
          pos += 4;
          sw_version = substr(data, pos, pos + len - 1);
          set_kb_item(name: "opcua/" + port + "/" + proto + "/version", value: sw_version);

          report = '\n\nThe following information was extracted:\n\n' +
                   "Product Name:     " + product_name + '\n' +
                   "Manufacturer:     " + manufacturer + '\n' +
                   "Software Version: " + sw_version + '\n';

          pos += len;
          len = getword(blob: data, pos: pos);
          pos += 4;
          if (len != 0) {
            build = substr(data, pos, pos + len - 1);
            report += "Build:            " + build;
            set_kb_item(name: "opcua/" + port + "/" + proto + "/build", value: build);
          }
          return report;
        }
      }
    }
  }
}
