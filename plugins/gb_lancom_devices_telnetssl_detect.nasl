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
  script_oid("1.3.6.1.4.1.25623.1.0.143423");
  script_version("2020-01-31T10:51:51+0000");
  script_tag(name:"last_modification", value:"2020-01-31 10:51:51 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 09:18:27 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (Telnet over SSL)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs Telnet over SSL based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_lancom_devices_telnet_detect.nasl");
  script_require_ports("Services/telnet", 992, 993);

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 992, ignore_broken: TRUE);

# Don't touch the ports already detected through gb_lancom_devices_telnet_detect.nasl
if (get_kb_item("lancom/telnet/" + port + "/detected"))
  exit(0);

banner = get_kb_item("FindService/tcp/" + port + "/get_http");
if (!banner)
  exit(0);

# | LANCOM 1783VAW (over ISDN)
# | Ver. 10.12.0488RU10 / 15.10.2018
# | SN.  4004619718100033
# | Copyright (c) LANCOM Systems
#
# A327, Connection No.: 002
#
# Password:
# Login Error
if ("| LANCOM" >< banner) {
  set_kb_item(name: "lancom/detected", value: TRUE);
  set_kb_item(name: "lancom/telnet_ssl/detected", value: TRUE);
  set_kb_item(name: "lancom/telnet_ssl/port", value: port);
  set_kb_item(name: "lancom/telnet_ssl/" + port + "/detected", value: TRUE);

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

  set_kb_item(name: "lancom/telnet_ssl/" + port + "/model", value: model);
  set_kb_item(name: "lancom/telnet_ssl/" + port + "/version", value: version);
  if (concluded)
    set_kb_item(name: "lancom/telnet_ssl/" + port + "/concluded", value: concluded);
}

exit(0);
