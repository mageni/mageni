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
  script_oid("1.3.6.1.4.1.25623.1.0.103799");
  script_version("2022-12-09T05:35:26+0000");
  script_tag(name:"last_modification", value:"2022-12-09 05:35:26 +0000 (Fri, 09 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-10-09 16:24:09 +0200 (Wed, 09 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco NX-OS Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP based detection of Cisco NX-OS.");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Cisco NX-OS(tm) n7000, Software (n7000-s1-dk9), Version 5.2(3a), RELEASE SOFTWARE Copyright (c) 2002-2011 by Cisco Systems, Inc. Compiled 12/15/2011 12:00:00;
# Cisco NX-OS(tm) ucs, Software (ucs-6100-k9-system), Version 5.0(3)N2(2.04b), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Compiled 10/21/2012 11:00:00
# Cisco NX-OS(tm) Nexus9000 C9300v, Software (NXOS 64-bit), Version 10.3(1), RELEASE SOFTWARE Copyright (c) 2002-2022 by Cisco Systems, Inc. Compiled 8/18/2022 15:00:00
if ("Cisco NX-OS" >!< sysdesc)
  exit(0);

version = "unknown";
device = "unknown";
model = "unknown";

set_kb_item(name: "cisco/nx_os/detected", value: TRUE);
set_kb_item(name: "cisco/nx_os/snmp/port", value: port);
set_kb_item(name: "cisco/nx_os/snmp/" + port + "/concluded", value: sysdesc);

vers = eregmatch(pattern: "Version ([0-9a-zA-Z\(\).]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

# N9K-C9300v
# Nexus7000 C7010 (10 Slot) Chassis
# N3K-C3064PQ-10GE
# Nexus 3064 Chassis
dev_mod_oid = "1.3.6.1.2.1.47.1.1.1.1.2.149";
dev_mod = snmp_get(port: port, oid: dev_mod_oid);

if ("Nexus" >< dev_mod || dev_mod =~ "^N[39]K") {
  device = "Nexus";

  mod = eregmatch(pattern: "^N[39]K-(.*)", string: dev_mod);
  if (!isnull(mod[1])) {
    model = mod[1];
  } else {
    mod = eregmatch(pattern: "Nexus[0-9]+?\s*([^\r\n\s]+)( Chassis)?", string: dev_mod);
    if (!isnull(mod[1]))
      model = mod[1];
  }

  set_kb_item(name: "cisco/nx_os/snmp/" + port + "/concludedModel", value: dev_mod);
  set_kb_item(name: "cisco/nx_os/snmp/" + port + "/concludedModelOID", value: dev_mod_oid);
} else if ("MDS" >< dev_mod) {
  device = "MDS";

  mod = eregmatch(pattern: "MDS\s*([^\r\n\s]+)", string: dev_mod);
  if (!isnull(mod))
    model = mod[1];

  set_kb_item(name: "cisco/nx_os/snmp/" + port + "/concludedModel", value: dev_mod);
  set_kb_item(name: "cisco/nx_os/snmp/" + port + "/concludedModelOID", value: dev_mod_oid);
}

if (device == "unknown") {
  if ("titanium" >< sysdesc) {
    device = "MDS";
  } else if (sysdesc =~ "Cisco NX-OS\(tm\) (n[0-9]+[^,]+)") {
    device = "Nexus";
    mod = eregmatch(pattern: "Cisco NX-OS\(tm\) n([0-9]+[^,]+)", string: sysdesc);
    if (!isnull(mod[1]))
      model = mod[1];
  }
}

set_kb_item(name: "cisco/nx_os/snmp/" + port + "/device", value: device);
set_kb_item(name: "cisco/nx_os/snmp/" + port + "/model", value: model);
set_kb_item(name: "cisco/nx_os/snmp/" + port + "/version", value: version);

exit(0);
