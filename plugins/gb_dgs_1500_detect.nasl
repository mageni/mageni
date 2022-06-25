###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dgs_1500_detect.nasl 9513 2018-04-17 14:26:07Z asteins $
#
# D-Link DGS-1500 Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.107252");
  script_version("$Revision: 9513 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-17 16:26:07 +0200 (Tue, 17 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-11-09 14:03:54 +0700 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DGS-1500 Detection");

  script_tag(name:"summary", value:"Detection of D-Link DGS-1500.

This script performs SNMP based detection of D-Link DGS-1500 devices.");

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
if ("DGS-1500" >< sysdesc)
{

  firmware = "unknown";
  ver = eregmatch(pattern: "(DGS-1500-[0-9]+)          ([0-9A-Z]+.*)", string: sysdesc);
  if (isnull(ver[1])) exit(0);

  model = ver[1];

  if (!isnull(ver[2])) firmware = ver[2];

  set_kb_item(name: "dgs/1500/model", value: model);
  set_kb_item(name: "dgs/1500/firmware", value: firmware);

  set_kb_item(name: "dgs/1500/detected", value: TRUE);

  cpe = build_cpe(value: firmware, exp: "^([0-9a-z.-]+)",
                  base: "cpe:/o:d-link:" + tolower(model) + "_firmware:");
  if (!cpe)
    cpe = 'cpe:/o:d-link:' + tolower(model) + "_firmware";

  register_product(cpe: cpe, port: port, location: port + "/udp", service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "D-Link  " + model, version: firmware,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
