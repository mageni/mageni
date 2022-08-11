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
  script_oid("1.3.6.1.4.1.25623.1.0.143706");
  script_version("2020-04-15T09:17:37+0000");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:28:52 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream GXP IP Phones Detection (Telnet)");

  script_tag(name:"summary", value:"Detection of Grandstream GXP IP Phones.

  This script performs Telnet based detection of Grandstream GXP IP Phones.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/grandstream/gxp/detected");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = telnet_get_port(default: 23);

if (!banner = telnet_get_banner(port: port))
  exit(0);

# Grandstream GXP2124 Command Shell Copyright 2011
# Grandstream GXP2000 Command Shell
if ("Grandstream GXP" >< banner) {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "grandstream/gxp/detected", value: TRUE);
  set_kb_item(name: "grandstream/gxp/telnet/port", value: port);
  set_kb_item(name: "grandstream/gxp/telnet/" + port + "/concluded", value: banner);

  mod = eregmatch(pattern: "Grandstream (GXP[0-9]+)", string: banner);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "grandstream/gxp/telnet/" + port + "/model", value: model);
  set_kb_item(name: "grandstream/gxp/telnet/" + port + "/version", value: version);
}

exit(0);
