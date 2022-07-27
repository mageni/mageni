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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142613");
  script_version("2019-07-22T13:49:29+0000");
  script_tag(name:"last_modification", value:"2019-07-22 13:49:29 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-18 06:44:09 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Hudson CI Detection (Auto Discovery)");

  script_tag(name:"summary", value:"The scripts tries to detect a Auto Discovery service of a Hudson CI
  server and to extract a possible exposed version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 33848);

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port(default: 33848, ipproto: "udp");

if (!soc = open_sock_udp(port))
  exit(0);

send(socket: soc, data: "\n");
recv = recv(socket: soc, length: 512);
close(soc);

if (!recv || "<hudson><" >!< recv || "<server-id>" >< recv)
  exit(0);

version = "unknown";

set_kb_item(name: "hudson/detected", value: TRUE);
set_kb_item(name: "hudson/autodiscovery/detected", value: TRUE);
set_kb_item(name: "hudson/autodiscovery/port", value: port);

# <hudson><version>1.367</version><slave-port>46809</slave-port></hudson>
# <hudson><version>3.0.0</version><url>http://www.example.com:8080/</url><slave-port>37639</slave-port></hudson>
vers = eregmatch(pattern: "<version>([0-9.]+)</version>", string: recv);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "hudson/autodiscovery/" + port + "/version", value: version);
set_kb_item(name: "hudson/autodiscovery/" + port + "/concluded", value: recv);

exit(0);
