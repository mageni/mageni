###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_protocol_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Moxa Management Protocol Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106693");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-24 14:13:08 +0700 (Fri, 24 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa Management Protocol Detection");

  script_tag(name:"summary", value:"Moxa's proprietary management protocol is running on UDP port 4800 at this
host.

It is used for Broadcast, Monitor, Get current settings, RealCOM Port mapping.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_udp_ports(4800);

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("moxa.inc");

port = 4800;

if (!get_udp_port_state(port))
  exit(0);

soc = open_sock_udp(port);
if (!soc)
  exit(0);

# Request device ID and MAC
query =  raw_string(0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00);
recv = moxa_send_recv(socket: soc, data: query);

if (strlen(recv) < 20 || hexstr(recv[0]) != "81" || hexstr(recv[1]) != "00") {
  close(soc);
  exit(0);
}

set_kb_item(name: "moxa_mgmt_proto/detected", value: TRUE);

# This data will be used for further requests
data = substr(recv, 4);
set_kb_item(name: "moxa_mgmt_proto/req_data", value: data);

model_data = substr(data, 4, 9);
model = moxa_get_model(data: model_data);

# Extract MAC
mac = substr(data, 10, 15);
mac = hexstr(mac[0]) + ':' + hexstr(mac[1]) + ':' + hexstr(mac[2]) + ':' + hexstr(mac[3]) + ':' + hexstr(mac[4]) +
      ':' + hexstr(mac[5]);
register_host_detail(name: "MAC", value: mac, desc: "gb_moxa_protocol_detect.nasl");
replace_kb_item(name: "Host/mac_address", value: mac);

# Query name info
query = raw_string(0x10, 0x00, 0x00, 0x14, data);
recv = moxa_send_recv(socket: soc, data: query);

if (strlen(recv) > 32) {
  name = substr(recv, 20);
  for (pos=0; pos<strlen(name); pos++) {
    if (hexstr(name[pos]) == "00")
      break;
  }
  name = substr(name, 0, pos-1);
}

# Query password setting status
query = raw_string(0x16, 0x00, 0x00, 0x14, data);
recv = moxa_send_recv(socket: soc, data: query);

if (hexstr(recv[0]) == "96" && strlen(recv) > 32) {
  if (hexstr(recv[32]) == "00")
    pw_enabled = "Authentication not enabled";
  else if (hexstr(recv[32]) == "01")
    pw_enabled = "Authentication enabled";
  else
    pw_enabled = "Authentication status unavailable";
}

register_service(port: port, ipproto: "udp", proto: "moxa mgmt");

report = "A Moxa Management service is running on this port.\n\nThe following information was extracted:\n\n" +
         "Model:                     " + model + "\n" +
         "MAC Address:               " + mac + "\n" +
         "Device Name:               " + name + "\n" +
         "Authentication status:     " + pw_enabled + "\n";

log_message(data: report, port: port, proto: "udp");

close(soc);

exit(0);
