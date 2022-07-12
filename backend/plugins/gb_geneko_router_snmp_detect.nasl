###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geneko_router_snmp_detect.nasl 9202 2018-03-26 08:18:46Z asteins $
#
# Geneko Router Detection (SNMP)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.107261");
  script_version("$Revision: 9202 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-26 10:18:46 +0200 (Mon, 26 Mar 2018) $");
  script_tag(name:"creation_date", value:"2017-11-17 14:42:26 +0700 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Geneko Router Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Geneko Router devices.

This script performs SNMP based detection of Geneko Router devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);

if(!sysdesc) exit(0);

if ("geneko" >< sysdesc) {

  version = "unknown";
  vers = eregmatch(pattern: "([0-9.]+)-geneko.*", string: sysdesc);

  if (isnull(vers[1]))
     vers = eregmatch(pattern: "geneko ([0-9.]+).*", string: sysdesc);

  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "geneko/version", value: version);
  }

  set_kb_item(name: "geneko/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:geneko:geneko:");
  if (!cpe)
    cpe = 'cpe:/o:geneko:geneko';

  register_product(cpe: cpe, port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "Geneko Router", version: version, install: "161/udp", cpe: cpe,
                                           concluded: sysdesc),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
