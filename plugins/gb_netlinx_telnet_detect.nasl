# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114079");
  script_version("$Revision: 14176 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:29:33 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-07 13:43:40 +0100 (Thu, 07 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetLinx Controller Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of NetLinx controller.

  The script sends a connection request to the server and attempts to detect the NetLinx controller via Telnet
  and to extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/netlinx/detected");

  script_xref(name:"URL", value:"https://www.amx.com/en-US/product_families/central-controllers");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");

port = get_telnet_port(default: 23);
banner = get_telnet_banner(port: port);
if(!banner || "Welcome to NetLinx" >!< banner)
  exit(0);

version = "unknown";
location = port + "/tcp";

#Welcome to NetLinx v3.60.453 Copyright AMX LLC 2010
ver = eregmatch(pattern: "Welcome to NetLinx v([0-9.]+)", string: banner, icase: TRUE);

if(ver[1])
  version = ver[1];

set_kb_item(name: "telnet/netlinx/port", value: port);
set_kb_item(name: "telnet/netlinx/version", value: version);

cpe = "cpe:/a:amx:netlinx_firmware:";

#Extra information -> show system
soc = open_sock_tcp(port);
if(soc) {
  send(socket: soc, data: 'show system\r\n');
  sysinfo = recv(socket: soc, length: 500);

  sysinfo = substr(sysinfo, 3, strlen(sysinfo));

  if("Local devices for system" >< sysinfo) {
    set_kb_item(name: "netlinx/telnet/unprotected", value: TRUE);
    set_kb_item(name: "netlinx/telnet/" + port + "/unprotected", value: TRUE);
  }
  telnet_close_socket(socket: soc, data: sysinfo);
}

app_cpe = "cpe:/a:amx:netlinx_firmware";
hw_cpe =  "cpe:/h:amx:netlinx_controller";

if(version) {
  app_cpe += ':' + version;
}

register_product(cpe: app_cpe, location: location, port: port, service: "telnet");
register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");

report = build_detection_report(app: "NetLinx Controller - Firmware", version: version,
                                install: location, cpe: app_cpe);
report += '\n\n';

report += build_detection_report(app: "NetLinx Controller - Device", skip_version: TRUE,
                                 install: location, cpe: hw_cpe);

if(sysinfo) {
  report += '\n\nConcluded from system information:\n' + sysinfo;
} else {
  report += '\n\nConcluded from banner:\n' + banner;
}

log_message(port: port, data: report);

exit(0);
