###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codesys_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# CODESYS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140500");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-16 08:54:19 +0700 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CODESYS Detection");

  script_tag(name:"summary", value:"A CODESYS Service is running at this host.

Over 250 device manufacturers from different industrial sectors offer intelligent automation devices with a
CODESYS programming interface.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1200, 2455, 4840);

  script_xref(name:"URL", value:"https://www.codesys.com");

  exit(0);
}

include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

# based on https://github.com/digitalbond/Redpoint/blob/master/codesys-v2-discover.nse

port = get_unknown_port(default: 2455);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# little endian query
lile_query = raw_string(0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01);
# big endian query
bige_query = raw_string(0xbb, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x01);

send(socket: soc, data: lile_query);
recv = recv(socket: soc, length: 512);

if (!recv) {
  send(socket: soc, data: bige_query);
  recv = recv(socket: soc, length: 512);
  if (!recv) {
    close(soc);
    exit(0);
  }
}

close(soc);

if (hexstr(substr(recv, 0, 1)) != "bbbb" || strlen(recv) < 130)
  exit(0);

set_kb_item(name: "codesys/detected", value: TRUE);

register_service(port: port, proto: "codesys");

os_name = bin2string(ddata:substr(recv, 64, 95), noprint_replacement: '');
set_kb_item(name: "codesys/os_name", value: os_name);
set_kb_item(name: "codesys/" + port + "/os_name", value: os_name);

os_details = bin2string(ddata:substr(recv, 96, 127), noprint_replacement: '');
set_kb_item(name: "codesys/os_details", value: os_details);
set_kb_item(name: "codesys/" + port + "/os_details", value: os_details);

type =  bin2string(ddata:substr(recv, 128, 159), noprint_replacement: '');

report = 'A CODESYS service is running at this port.\n\nThe following information was extracted:\n\n' +
         'OS Name:       ' + os_name + '\n' +
         'OS Details:    ' + os_details + '\n' +
         'Product Type:  ' + type;

log_message(port: port, data: report);
exit(0);