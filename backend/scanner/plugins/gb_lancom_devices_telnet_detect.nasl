# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143422");
  script_version("2020-01-31T10:51:51+0000");
  script_tag(name:"last_modification", value:"2020-01-31 10:51:51 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 08:46:45 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs Telnet based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/lancom/detected");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);
if (!banner)
  exit(0);

# | LANCOM 1611+
# | Ver. 8.82.0100RU1 / 28.08.2013
# | SN.  202321800137
# | Copyright (c) LANCOM Systems
#
# aquafil, Connection No.: 002 (LAN)
#
# Password:
if ("| LANCOM" >< banner) {
  set_kb_item(name: "lancom/detected", value: TRUE);
  set_kb_item(name: "lancom/telnet/detected", value: TRUE);
  set_kb_item(name: "lancom/telnet/port", value: port);
  set_kb_item(name: "lancom/telnet/" + port + "/detected", value: TRUE);

  version = "unknown";
  model = "unknown";

  mod = eregmatch(pattern: 'LANCOM ([^\n\r]+)', string: banner);
  if (!isnull(mod[1])) {
    model = mod[1];
    concluded = '\n    ' + mod[0];
  }

  vers = eregmatch(pattern: "Ver\. ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n    ' + vers[0];
  }

  set_kb_item(name: "lancom/telnet/" + port + "/model", value: model);
  set_kb_item(name: "lancom/telnet/" + port + "/version", value: version);
  if (concluded)
    set_kb_item(name: "lancom/telnet/" + port + "/concluded", value: concluded);
}

exit(0);
