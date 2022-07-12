###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_westermo_weos_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Westermo WeOS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106196");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-24 11:10:05 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Westermo WeOS Detection");

  script_tag(name:"summary", value:"Detection of Westermo WeOS

This script performs SNMP based detection of Westermo WeOS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"http://www.westermo.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if (egrep(string: sysdesc, pattern: "^Westermo.*, primary:.*, backup:.*, bootloader:")) {
  model = "unknown";
  version = "unknown";

  mo = eregmatch(pattern: "Westermo (.*), primary:", string: sysdesc);
  if (!isnull(mo[1]))
    model = mo[1];

  vers = eregmatch(pattern: "primary: v([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "westermo_weos/detected", value: TRUE);
  if (model != "unknown")
    set_kb_item(name: "westermo_weos/model", value: model);
  if (version != "unknown")
    set_kb_item(name: "westermo_weos/version", value: version);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:westermo:weos:");
  if (!cpe)
    cpe = 'cpe:/o:westermo:weos';

  register_product(cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp");

  log_message(data: build_detection_report(app: "Westermo WeOS on model " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");

  exit(0);
}

exit(0);
