# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149481");
  script_version("2023-04-06T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-04-06 10:08:49 +0000 (Thu, 06 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 06:16:33 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Service Location Protocol (SLP) Detection (TCP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 427);

  script_tag(name:"summary", value:"TCP based detection of services supporting the Service Location
  Protocol (SLP).");

  script_xref(name:"URL", value:"https://www.ietf.org/rfc/rfc2608.html");
  script_xref(name:"URL", value:"http://www.openslp.org/");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("slp_func.inc");

debug = FALSE;

port = unknownservice_get_port(default: 427);

if (!soc = open_sock_tcp(port))
  exit(0);

req_xid = rand() % 0xffff; # nb: Limiting the XID a little...

# TBD: We might want to check for a "service:directory-agent" here as well in the future
msg_exts = make_array("service_type_list", "service:service-agent",
                      "scope_list", "default",
                      "lang_tag", "en");

service_request = slp_create_message(func_id: SLP_MESSAGES_RAW["SrvRqst"], msg_exts: msg_exts, xid: req_xid, debug: debug);

send(socket: soc, data: service_request);
recv = recv(socket: soc, length: 512);
close(soc);

if (!recv)
  exit(0);

# nb: The function has already some basic response checks like an sufficient length of the response
# or to check if the only supported version 2 was returned...
if (!infos = slp_parse_response(data: recv, debug: debug))
  exit(0);

# nb: From https://www.ietf.org/rfc/rfc2608.html#section-8:
# > Replies set the XID to the same value as the xid in the request. Only unsolicited DAAdverts are
# > sent with an XID of 0.
# As we don't expect a DAAdvers here we're checking only for the correct XID we had passed
# previously.
res_xid = infos["xid"];
if (req_xid != res_xid) {
  if (debug) display("DEBUG: Received XID '" + res_xid + "' doesn't match expected XID '" + req_xid + "'.");
  exit(0);
}

res_func = infos["func_id_string"];
if (res_func != "SAAdvert (SA Advertisement)") {
  if (debug) display("DEBUG: Received Function-ID '" + res_func + "' doesn't match expected Function-ID 'SAAdvert (SA Advertisement)'.");
  exit(0);
}

set_kb_item(name: "slp/detected", value: TRUE);
set_kb_item(name: "slp/tcp/detected", value: TRUE);

service_register(port: port, proto: "slp");

# TBD: In the future we could also use the parsed/returned data from slp_parse_response() here...
report = 'A service supporting the Service Location Protocol (SLP) is running at this port.\n\nResponse:\n\n' +
         bin2string(ddata: recv, noprint_replacement: " ");

log_message(port: port, data: chomp(report));

exit(0);
