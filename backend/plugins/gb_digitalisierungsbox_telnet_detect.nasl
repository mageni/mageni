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
  script_oid("1.3.6.1.4.1.25623.1.0.143197");
  script_version("2019-12-09T16:17:09+0000");
  script_tag(name:"last_modification", value:"2019-12-09 16:17:09 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-28 06:42:27 +0000 (Thu, 28 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Digitalisierungsbox Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Digitalisierungsbox.

  This script performs Telnet based detection of Digitalisierungsbox devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, 2323);
  script_mandatory_keys("telnet/digitalisierungsbox/detected");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 2323);

if (!banner = telnet_get_banner(port: port))
  exit(0);

# Welcome to Digitalisierungsbox Premium version 10.2.01.104 from 2018/10/25 00:00:00
if ("Digitalisierungsbox" >< banner) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "digitalisierungsbox/detected", value: TRUE);
  set_kb_item(name: "digitalisierungsbox/telnet/port", value: port);

  vers = eregmatch(pattern: "version ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "digitalisierungsbox/telnet/" + port + "/concluded", value: vers[0]);
  }

  mod = eregmatch(pattern: "Digitalisierungsbox (STANDARD|BASIC|SMART|PREMIUM)", string: banner, icase: TRUE);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "digitalisierungsbox/telnet/" + port + "/model", value: model);
  set_kb_item(name: "digitalisierungsbox/telnet/" + port + "/version", value: version);
}

exit(0);
