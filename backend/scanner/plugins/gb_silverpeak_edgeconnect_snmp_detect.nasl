###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_silverpeak_edgeconnect_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Silver Peak EdgeConnect Detection (SNMP)
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
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-23 12:36:07 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Silver Peak EdgeConnect Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Silver Peak EdgeConnect
devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);

if (!sysdesc = get_snmp_sysdesc(port: port))
  exit(0);

if ("Silver Peak Systems" >!< sysdesc && "VXOA " >!< sysdesc)
  exit(0);

set_kb_item(name: "silverpeak_edgeconnect/detected", value: TRUE);

# Silver Peak Systems, Inc. ECV
#Linux REG-GTW-FRANKFURT 2.6.38.6-rc1 #1 VXOA 8.1.8.0_71257 SMP Mon Jun 18 15:28:45 PDT 2018 x86_64
mod = eregmatch(pattern: "Silver Peak Systems, Inc. (EC(V|XS))", string: sysdesc);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: "silverpeak_edgeconnect/model", value: model);
}

version = "unknown";

vers = eregmatch(pattern: "VXOA ([0-9.]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:silver-peak:vx:");
if (!cpe)
  cpe = 'cpe:/a:silver-peak:vx';

register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp");

log_message(data: build_detection_report(app: "Silver Peak EdgeConnect " + model, version: version,
                                         install: port + "/udp", cpe: cpe, concluded: sysdesc),
            port: port, proto: "udp");

exit(0);
