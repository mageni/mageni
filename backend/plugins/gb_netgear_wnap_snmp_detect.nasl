###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnap_snmp_detect.nasl 12586 2018-11-29 18:04:39Z cfischer $
#
# NETGEAR WNAP/WNDAP Device Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141738");
  script_version("$Revision: 12586 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 19:04:39 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-29 15:40:51 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR WNAP/WNDAP Device Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of NETGEAR WNAP/WNDAP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_ports("Services/www", 80, 443);
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);
sysdesc = get_snmp_sysdesc(port: port);

# e.g. Linux WNDAP350 2.6.23-WNDAP350_V3.7.9.0-gaecb3146-dirty #1 Mon Oct 9 03:43:23 PDT 2017 mips
if (!sysdesc || ("Linux" >!< sysdesc || sysdesc !~ "WND?AP[0-9]{3}"))
  exit(0);

set_kb_item(name: "netgear_wnap/detected", value: TRUE);
set_kb_item(name: "netgear_wnap/snmp/detected", value: TRUE);
set_kb_item(name: "netgear_wnap/snmp/port", value: port);

model = "unknown";
fw_version = "unknown";

mod_vers = eregmatch(pattern: "(WND?AP[0-9]+)_V([0-9.]+)", string: sysdesc);
if (!isnull(mod_vers[1]))
  model = mod_vers[1];
if (!isnull(mod_vers[2]))
  fw_version = mod_vers[2];

set_kb_item(name: "netgear_wnap/snmp/" + port + "/model", value: model);
set_kb_item(name: "netgear_wnap/snmp/" + port + "/fw_version", value: fw_version);
set_kb_item(name: "netgear_wnap/snmp/" + port + "/concluded", value: sysdesc);

exit(0);