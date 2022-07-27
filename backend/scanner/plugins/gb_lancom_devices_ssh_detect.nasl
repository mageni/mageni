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
  script_oid("1.3.6.1.4.1.25623.1.0.143418");
  script_version("2020-01-31T10:51:51+0000");
  script_tag(name:"last_modification", value:"2020-01-31 10:51:51 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 06:59:00 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (SSH)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs SSH based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/lancom/detected");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default: 22);
banner = get_ssh_server_banner(port: port);
if (!banner)
  exit(0);

# SSH-2.0-lancom
if (egrep(pattern: "SSH.+-lancom", string: banner)) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "lancom/detected", value: TRUE);
  set_kb_item(name: "lancom/ssh/detected", value: TRUE);
  set_kb_item(name: "lancom/ssh/port", value: port);
  set_kb_item(name: "lancom/ssh/" + port + "/detected", value: TRUE);
  set_kb_item(name: "lancom/ssh/" + port + "/version", value: version);
  set_kb_item(name: "lancom/ssh/" + port + "/model", value: version);
  set_kb_item(name: "lancom/ssh/" + port + "/concluded", value: banner);
}

exit(0);
