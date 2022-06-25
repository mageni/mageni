###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qlogic_switch_module_snmp_detect.nasl 12427 2018-11-20 03:39:33Z ckuersteiner $
#
# QLogic Switch Module for IBM BladeCenter Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.141703");
  script_version("$Revision: 12427 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 04:39:33 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-20 09:29:04 +0700 (Tue, 20 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QLogic Switch Module for IBM BladeCenter Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of QLogic Switch Module for IBM BladeCenter

This script performs SNMP based detection of QLogic Switch Module for IBM BladeCenter.");

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
sysdesc = get_snmp_sysdesc(port: port);
if (!sysdesc)
  exit(0);

# QLogic(R) 20-Port 4/8 Gb SAN Switch Module for IBM BladeCenter(R)
if (sysdesc =~ "QLogic.*Switch Module for IBM BladeCenter") {
  version = "unknown";

  mo = eregmatch(pattern: "QLogic[^ ]+ (.*) Switch", string: sysdesc);
  if (!isnull(mo[1]))
    model = mo[1];
  else
    exit(0);

  set_kb_item(name: "qlogic_switchmodule/detected", value: TRUE);
  set_kb_item(name: "qlogic_switchmodule/model", value: model);

  cpe = 'cpe:/h:qlogic:switch_module_firmware';

  register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "QLogic " + model + " Switch Module for IBM BladeCenter",
                                           version: version, install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");
  exit(0);
}

exit(0);
