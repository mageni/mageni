# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.144534");
  script_version("2020-09-08T06:57:40+0000");
  script_tag(name:"last_modification", value:"2020-09-09 09:59:16 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-08 06:13:55 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys Device Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Linksys devices.");

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

# Linux Free-Linksys 4.4.93 #0 SMP Wed Oct 18 21:27:17 2017 armv7l
# Linux Linksys WRT400N 3.18.140-d4 #80628 Thu Jun 4 02:21:16 +04 2020 mips
if (egrep(pattern: "Linksys", string: sysdesc, icase: TRUE)) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "linksys/detected", value: TRUE);
  set_kb_item(name: "linksys/snmp/port", value: port);
  set_kb_item(name: "linksys/snmp/" + port + "/concluded", value: sysdesc);

  mod = eregmatch(pattern: "Linksys ([A-Z]+[^ ]+)", string: sysdesc, icase: TRUE);
  if (!isnull(mod[1]))
    model = mod[1];

  set_kb_item(name: "linksys/snmp/" + port + "/model", value: model);
  set_kb_item(name: "linksys/snmp/" + port + "/version", value: version);
}

exit(0);
