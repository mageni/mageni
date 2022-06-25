# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.145817");
  script_version("2021-04-28T07:12:47+0000");
  script_tag(name:"last_modification", value:"2021-04-29 10:46:31 +0000 (Thu, 29 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-23 05:11:18 +0000 (Fri, 23 Apr 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Datagram Transport Layer Security (DTLS) Detection");

  script_tag(name:"summary", value:"A Datagram Transport Layer Security (DTLS) enabled Service is
  running at this port.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("global_settings.nasl", "gb_open_udp_ports.nasl");
  script_require_udp_ports(443, 601, 853, 2221, 3391, 3478, 4433, 4740, 4755, 5061, 5246, 5247, 5349, 5684, 5868, 6514, 8232, 10161, 10162);

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("ssl_funcs.inc");
include("dtls_func.inc");
include("dump.inc");

default_ports = make_list(443,            # Cisco/F5 VPN, Citrix Netscaler Gateway
                          601,            # Syslog
                          853,            # DNS
                          2221,           # Ethernet/IP
                          3391,           # Microsoft Remote Desktop Gateway (RDG)
                          3478,           # STUN
                          4433,           # F5 Network Access VPN
                          4740,           # ipfix
                          4755,           # GRE-UDP-DTLS
                          5061,           # SIP
                          5246,           # CAPWAP
                          5247,           # CAPWAP
                          5349,           # STUN
                          5684,           # CoAP
                          5868,           # Diameter
                          6514,           # Syslog
                          8232,           # HNCP
                          10161,          # SNMP
                          10162);         # SNMP

port_list = unknownservice_get_ports(default_port_list: default_ports, ipproto: "udp");

foreach port (port_list) {
  if (!get_udp_port_state(port))
    continue;

  if (service_is_known(port: port, ipproto: "udp"))
    continue;

  soc = open_sock_udp(port);
  if (!soc)
    continue;

  seq_num = dtls_client_hello(socket: soc);
  if (isnull(seq_num)) {
    close(soc);
    continue;
  }

  if (seq_num != -1)
    dtls_send_alert(socket: soc, seq_num: seq_num);

  set_kb_item(name: "dtls/" + port + "/detected", value: TRUE);

  service_register(port: port, proto: "dtls", ipproto: "udp");

  report = "A DTLS enabled service is running at this port.";

  if (seq_num == -1) {
    report += '\n\nThe server responded with an "Alert" Message';
    set_kb_item(name: "dtls/" + port + "/alert_received", value: TRUE);
  }

  log_message(port: port, data: report, proto: "udp");
}

exit(0);
