# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149246");
  script_version("2023-03-03T10:59:40+0000");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-08 07:08:39 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Service Location Protocol (SLP) Service Detection (UDP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 427);

  script_tag(name:"summary", value:"UDP based detection of services supporting the Service Location
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

port = unknownservice_get_port(default: 427, ipproto: "udp");

if (!soc = open_sock_udp(port))
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
set_kb_item(name: "slp/udp/detected", value: TRUE);

service_register(port: port, proto: "slp", ipproto: "udp");

# TBD: In the future we could also use the parsed/returned data from slp_parse_response() here...
report = 'A service supporting the Service Location Protocol (SLP) is running at this port.\n\nResponse:\n\n' +
         bin2string(ddata: recv, noprint_replacement: " ");

log_message(port: port, proto: "udp", data: chomp(report));

exit(0);
