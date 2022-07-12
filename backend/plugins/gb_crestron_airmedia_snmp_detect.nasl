###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_crestron_airmedia_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Crestron AirMedia Presentation Gateway Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141392");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-23 16:34:16 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron AirMedia Presentation Gateway Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Crestron AirMedia Presentation
Gateway devices.");

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

if ("Crestron Electronics AM-" >!< sysdesc)
  exit(0);

# Crestron Electronics AM-100 (Version 1.4.0.13)
mod = eregmatch(pattern: "Crestron Electronics (AM\-[0-9]+)", string: sysdesc);
if (isnull(mod[1]))
  exit(0);

model = mod[1];

version = "unknown";

vers = eregmatch(pattern: "Version ([0-9.]+)", string: sysdesc);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "crestron_airmedia/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:crestron:" + tolower(model) + ":");
if (!cpe)
  cpe = 'cpe:/o:crestron:' + tolower(model);

register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp");

log_message(data: build_detection_report(app: "Crestron " + model, version: version, install: port + "/udp",
                                         cpe: cpe),
            port: port, proto: "udp");

exit(0);
