###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netscaler_snmp_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# Citrix Netscaler Detection (SNMP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.140666");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix Netscaler Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Citrix Netscaler

This script performs SNMP based detection of Citrix Netscaler.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"https://www.citrix.com/products/netscaler-adc/");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);
sysdesc = get_snmp_sysdesc(port: port);

if (!sysdesc || sysdesc !~ "^NetScaler NS")
  exit(0);

set_kb_item(name: "citrix_netscaler/detected", value: TRUE);
set_kb_item(name: "citrix_netscaler/snmp/detected", value: TRUE);
set_kb_item(name: "citrix_netscaler/snmp/port", value: port);

version = "unknown";

# NetScaler NS12.0: Build 53.22.nc, Date: Dec 10 2017, 04:46:16
# NetScaler NS10.5: Build 60.7066.e.nc, Date: Nov 18 2016, 14:29:31
vers = eregmatch(pattern: "^NetScaler NS([0-9\.]+): (Build (([0-9\.]+))(.e)?.nc)?", string: sysdesc);
if (!isnull(vers[1])) {
  if (!isnull(vers[3]))
    version = vers[1] + "." + vers[3];
  else
    version = vers[1];

  # Enhanced Build
  if (!isnull(vers[5]))
    set_kb_item(name: "citrix_netscaler/enhanced_build", value: TRUE);

  set_kb_item(name: "citrix_netscaler/snmp/" + port + "/version", value: version);
  set_kb_item(name: "citrix_netscaler/snmp/" + port + "/concluded", value: sysdesc);
}

exit(0);
