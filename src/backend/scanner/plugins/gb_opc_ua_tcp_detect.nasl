# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140050");
  script_version("2023-08-09T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-11-03 14:59:49 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("OPC UA Detection (TCP)");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 4840);

  script_tag(name:"summary", value:"TCP based detection of services supporting the OPC Unified
  Architecture (OPC UA) protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("byte_func.inc");
include("opcua.inc");

proto = "tcp";

port = unknownservice_get_port(default: 4840);
# nb: Should be always before the first open_sock_tcp() call.
host = get_host_name();

if (!soc = open_sock_tcp(port))
  exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

opc_req_header = raw_string("HEL",   # Message Type (Hello)
                            "F");    # Chunk Type

endpoint_url = "opc." + proto + "://" + host + ":" + port;

epu_len = strlen(endpoint_url);
epu_len = mkdword(epu_len);

opc_req_footer = raw_string(0x00, 0x00, 0x00, 0x00,                      # Version (0)
                            0x00, 0x00, 0x01, 0x00,                      # ReceiveBufferSeize (65536)
                            0x00, 0x00, 0x01, 0x00,                      # SendBufferSize (65536)
                            0x00, 0x00, 0x00, 0x00,                      # MaxMessageSize (0)
                            0x00, 0x00, 0x00, 0x00,                      # MaxChunkCount (0)
                            epu_len,                                     # EndPointUrlLen
                            endpoint_url);                               # EndPointUrl

l = (strlen(opc_req_header) + strlen(opc_req_footer) + 4);

len = mkdword(l);

opc_req = opc_req_header + len + opc_req_footer;

send(socket: soc, data: opc_req);
recv = recv(socket: soc, length: 4);

if (strlen(recv) != 4 || (recv !~ "^ACKF" && recv !~ "^ERRF")) {
  close(soc);
  exit(0);
}

set_kb_item(name: "opcua/detected", value: TRUE);
set_kb_item(name: "opcua/proto", value: proto);
set_kb_item(name: "opcua/" + proto + "/detected", value: TRUE);
set_kb_item(name: "opcua/" + port + "/" + proto + "/detected", value: TRUE);
set_kb_item(name: "opcua/" + port + "/proto", value: proto);

service_register(port: port, proto: "opc-ua", ipproto: proto);

extra = opcua_gather_device_info(socket: soc, proto: proto, port: port, endpoint_url: endpoint_url);

close(soc);

report = "A service supporting the OPC UA protocol is running at this port.";
if (extra)
  report += extra;

log_message(port: port, data: report, proto: proto);

exit(0);
