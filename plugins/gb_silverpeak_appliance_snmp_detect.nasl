###############################################################################
# OpenVAS Vulnerability Test
#
# Silver Peak Appliance Detection (SNMP)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141389");
  script_version("2019-09-30T13:57:26+0000");
  script_tag(name:"last_modification", value:"2019-09-30 13:57:26 +0000 (Mon, 30 Sep 2019)");
  script_tag(name:"creation_date", value:"2018-08-23 12:36:07 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Silver Peak Appliance Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs an SNMP based detection of Silver Peak appliances.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);

if (!sysdesc = get_snmp_sysdesc(port: port))
  exit(0);

if (sysdesc !~ "Silver Peak Systems, Inc\. (EC|NX|VX)" || "VXOA " >!< sysdesc)
  exit(0);

set_kb_item(name: "silverpeak_appliance/detected", value: TRUE);
set_kb_item(name: "silverpeak_appliance/snmp/detected", value: TRUE);
set_kb_item(name: "silverpeak_appliance/snmp/port", value: port);
set_kb_item(name: "silverpeak_appliance/snmp/" + port + "/concluded", value: sysdesc);

#Silver Peak Systems, Inc. ECV
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.8.0_71257 SMP Mon Jun 18 15:28:45 PDT 2018 x86_64
#
#Silver Peak Systems, Inc. ECXS
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.9.3_74197 SMP Tue Jan 29 16:46:04 PST 2019 x86_64
#
#Silver Peak Systems, Inc. ECXL
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.7.14_72871 SMP Thu Oct 11 01:20:43 PDT 2018 x86_64
#
#Silver Peak Systems, Inc. ECM
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.6.0_67090 SMP Fri Sep 15 17:35:59 PDT 2017 x86_64
#
#Based on -> https://www.silver-peak.com/products/wan-optimization/nx-physical-appliances
#Silver Peak Systems, Inc. NX11k
#Linux ...
#
#Silver Peak Systems, Inc. NX5700
#Linux $hostname 2.6.38.6-rc1 #1 VXOA 8.1.5.9_69125 SMP Wed Feb 28 14:54:46 PST 2018 x86_64
#
mod = eregmatch(pattern: "Silver Peak Systems, Inc. ((EC(V|XS|S|M|L|XL))|NX[0-9]+k?|VX[0-9]+)", string: sysdesc);
if (!isnull(mod[1]))
  set_kb_item(name: "silverpeak_appliance/snmp/" + port + "/model", value: mod[1]);

vers = eregmatch(pattern: "VXOA ([0-9._]+)", string: sysdesc);
if (!isnull(vers[1]))
  set_kb_item(name: "silverpeak_appliance/snmp/" + port + "/version", value: vers[1]);

exit(0);
