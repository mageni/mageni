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
  script_oid("1.3.6.1.4.1.25623.1.0.143662");
  script_version("2020-03-31T10:12:07+0000");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-31 08:53:09 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Router Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of DrayTek Vigor Router.

  This script performs SNMP based detection of DrayTek Vigor Router.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# DrayTek Corporation, Router Model: Vigor2960, Version: 1.4.4_Beta/1.4.4, Build Date/Time: 2019-07-07 23:29:57
# DrayTek Corporation, Router Model: Vigor2860 Series, Version: 3.8.9.4_STD, Build Date/Time:Jan 30 2019 15:54:34, CPU Usage: 6%, Memory Usage:86%

if (sysdesc !~ "^DrayTek.+Router Model")
  exit(0);

set_kb_item(name: "draytek/vigor/router/detected", value: TRUE);
set_kb_item(name: "draytek/vigor/router/snmp/port", value: port);
set_kb_item(name: "draytek/vigor/router/snmp/" + port + "/concluded", value: sysdesc);

model = "unknown";
version = "unknown";

mod = eregmatch(pattern: "Router Model: Vigor([0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

vers = eregmatch(pattern: "Version: ([^/,]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "draytek/vigor/router/snmp/" + port + "/model", value: model);
set_kb_item(name: "draytek/vigor/router/snmp/" + port + "/version", value: version);

exit(0);
