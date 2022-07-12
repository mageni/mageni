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
  script_oid("1.3.6.1.4.1.25623.1.0.144401");
  script_version("2020-08-17T07:22:08+0000");
  script_tag(name:"last_modification", value:"2020-08-25 10:44:06 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 03:16:46 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business Switch Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Cisco Small Business Switch devices.");

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

if (!sysdesc = snmp_get_sysdesc(port: port))
  exit(0);

# SG250-50 50-Port Gigabit Smart Switch
# SG300-10 10-Port Gigabit Managed Switch
# SG500-52 52-Port Gigabit Stackable Managed Switch
# SG300-28PP 28-Port Gigabit PoE+ Managed Switch
if (sysdesc !~ "^S(G|F)[0-9]{3}.*(Stackable Managed|Managed|Smart) Switch$")
  exit(0);

model = "unknown";
version = "unknown";

set_kb_item(name: "cisco/sb_switch/detected", value: TRUE);
set_kb_item(name: "cisco/sb_switch/snmp/port", value: port);
set_kb_item(name: "cisco/sb_switch/snmp/" + port + "/concluded", value: sysdesc);

mod = eregmatch(pattern: "^(S[GF][^ ]+)", string: sysdesc);
if (!isnull(mod[1]))
  model = mod[1];

if (model =~ "^S[GF][2]" || model =~ "^S[GF][0-9]{3}X") {
  oid = "1.3.6.1.2.1.47.1.1.1.1.10.67109120";
  vers = snmp_get(port: port, oid: oid);
  if (vers =~ "^[0-9]+\.") {
    version = vers;
    set_kb_item(name: "cisco/sb_switch/snmp/" + port + "/concludedOID", value: oid);
  }
} else if (model =~ "^S[GF][35]") {
  oid = "1.3.6.1.2.1.47.1.1.1.1.10.67108992";
  vers = snmp_get(port: port, oid: oid);
  if (vers =~ "^[0-9]+\.") {
    version = vers;
    set_kb_item(name: "cisco/sb_switch/snmp/" + port + "/concludedOID", value: oid);
  }
}

set_kb_item(name: "cisco/sb_switch/snmp/" + port + "/model", value: model);
set_kb_item(name: "cisco/sb_switch/snmp/" + port + "/version", value: version);

exit(0);
