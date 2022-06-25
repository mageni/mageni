###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cambium_cnpilot_snmp_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# Cambium Networks cnPilot Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140629");
  script_version("$Revision: 10888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-12-22 16:10:50 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Cambium Networks cnPilot

This script performs SNMP based detection of Cambium Networks cnPilot.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/wifi/");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);
sysdesc = get_snmp_sysdesc(port: port);

if (!sysdesc || sysdesc !~ "^cnPilot")
  exit(0);

set_kb_item(name: "cambium_cnpilot/detected", value: TRUE);
set_kb_item(name: "cambium_cnpilot/snmp/detected", value: TRUE);
set_kb_item(name: "cambium_cnpilot/snmp/port", value: port);

model = "unknown";
fw_version = "unknown";

# cnPilot R200P 4.3.1-R1
mod = eregmatch(pattern: "cnPilot ([^ ]+)", string: sysdesc);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "cambium_cnpilot/snmp/" + port + "/model", value: model);
}

vers = eregmatch(pattern: "cnPilot " + model + " ([0-9.]+-R.*)", string: sysdesc);
if (!isnull(vers[1])) {
  fw_version = vers[1];
  set_kb_item(name: "cambium_cnpilot/snmp/" + port + "/fw_version", value: fw_version);
}

exit(0);
