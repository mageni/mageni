###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coship_router_snmp_detect.nasl 13109 2019-01-17 07:42:10Z ckuersteiner $
#
# Coship WiFi Router Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141883");
  script_version("$Revision: 13109 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 08:42:10 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-17 13:33:08 +0700 (Thu, 17 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Coship WiFi Router Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of HShenzhen Coship Electronics WiFi Router

This script performs SNMP based detection of Shenzhen Coship Electronics WiFi Routers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"http://en.coship.com/index.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default: 161);
sysdesc = get_snmp_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# Shenzhen Coship Electronics RT3050 WiFi Router, SW version: 4.0.0.40
if ("Shenzhen Coship Electronic" >< sysdesc) {
  version = "unknown";

  vers = eregmatch(pattern: "Shenzhen Coship Electronics ([^ ]+)[^,]+, SW version: ([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    model = vers[1];
  else
    exit(0);

  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name: "coship_router/detected", value: TRUE);
  set_kb_item(name: "coship_router/model", value: model);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:coship:" + tolower(model) + ":");
  if (!cpe)
    cpe = "cpe:/h:coship:" + tolower(model);

  register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "Shenzhen Coship Electronics " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");
  exit(0);
}

exit(0);
