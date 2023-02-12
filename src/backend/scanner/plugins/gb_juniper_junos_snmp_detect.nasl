# Copyright (C) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103809");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2013-10-14 14:24:09 +0200 (Mon, 14 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Juniper Networks Junos OS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Juniper Networks Junos OS.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

if (!sysdesc = snmp_get_sysdescr(port: port))
  exit(0);

# Juniper Networks, Inc. ex3200-24t internet router, kernel JUNOS 10.1R1.8 #0: 2010-02-12 17:24:20 UTC ...
# Juniper Networks, Inc. m320 internet router, kernel JUNOS 10.1R3.7 #0: 2010-07-10 05:44:37 UTC ...
# Juniper Networks, Inc. srx210be internet router, kernel JUNOS 10.4R4.5 #0: 2011-05-06 06:14:23 UTC ...
# Juniper Networks, Inc. mx960 internet router, kernel JUNOS 21.2R3-S2.9, Build date: ...
# Juniper Networks, Inc. srx340 internet router, kernel JUNOS 15.1X49-D150.2, Build date: ...
# Juniper Networks, Inc. qfx10002-36q Ethernet Switch, kernel JUNOS 18.4R2-S5.4, Build date: ...
if (sysdesc !~ "^Juniper Networks" || "kernel JUNOS" >!< sysdesc)
  exit(0);

version = "unknown";
model = "unknown";
build = "unknown";

set_kb_item(name: "juniper/junos/detected", value: TRUE);
set_kb_item(name: "juniper/junos/snmp/port", value: port);
set_kb_item(name: "juniper/junos/snmp/" + port + "/concluded", value: sysdesc);

vers = eregmatch(pattern: "JUNOS ([0-9.]+[A-Z][^ ,]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

mod_oid = "1.3.6.1.4.1.2636.3.1.2.0";
mod = snmp_get(port: port, oid: mod_oid);
# Juniper SRX210be Internet Router
# Juniper QFX10002-36Q Switch
# Juniper MX960 Internet Backbone Router
mod_extract = eregmatch(pattern: "^Juniper ([^ ]+)", string: mod);
if (!isnull(mod_extract[1])) {
  model = mod_extract[1];
  set_kb_item(name:"juniper/junos/snmp/" + port + "/concludedMod", value: mod);
  set_kb_item(name:"juniper/junos/snmp/" + port + "/concludedModOID", value: mod_oid);
}

bld = eregmatch(pattern: "Build date: ([^ ]+)", string: sysdesc);
if (!isnull(bld[1]))
  build = bld[1];

set_kb_item(name: "juniper/junos/snmp/" + port + "/version", value: version);
set_kb_item(name: "juniper/junos/snmp/" + port + "/model", value: model);
set_kb_item(name: "juniper/junos/snmp/" + port + "/build_date", value: build);

exit(0);
