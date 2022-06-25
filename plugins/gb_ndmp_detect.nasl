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
  script_oid("1.3.6.1.4.1.25623.1.0.140215");
  script_version("2019-06-21T04:23:37+0000");
  script_tag(name:"last_modification", value:"2019-06-21 04:23:37 +0000 (Fri, 21 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-19 06:17:59 +0000 (Wed, 19 Jun 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Network Data Management Protocol (NDMP) Detection");

  script_tag(name:"summary", value:"A NDMP Service is running at this host.

  NDMP is used primarily for backup of network-attached storage (NAS) devices, such as storage systems.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 10000);

  script_xref(name:"URL", value:"https://www.snia.org/ndmp");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("misc_func.inc");

if (!port = get_unknown_port(default: 10000))
  exit(0);

if (!soc = open_sock_tcp(port))
  exit(0);

# nb: Wait for the NOTIFY_CONNECTED message from the server
recv = recv(socket: soc, length: 4);
if (!recv || hexstr(recv) !~ "^800000") {
  close(soc);
  exit(0);
}

len = getdword(blob: recv, pos: 0) & 0x7fffffff;
if (len < 24 || len > 100) {
  close(soc);
  exit(0);
}

hexbanner = recv;

recv = recv(socket: soc, length: len);
if (!recv || strlen(recv) != len) {
  close(soc);
  exit(0);
}

hexbanner += recv;

close(soc);

# NDMP Sequence should be 1
if (hexstr(substr(recv, 0, 3)) != "00000001")
  exit(0);

register_service(port: port, ipproto: "tcp", proto: "ndmp");

set_kb_item(name: "ndmp/" + port + "/hex_banner", value: hexstr(hexbanner));

report = 'A Network Data Management Protocol (NDMP) service is running on this port.';
log_message(data: report, port: port);

exit(0);
