###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_version_snmp.nasl 7236 2017-09-22 14:59:19Z cfischer $
#
# Cisco ASA Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106513");
  script_version("$Revision: 7236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-22 16:59:19 +0200 (Fri, 22 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-01-12 15:23:14 +0700 (Thu, 12 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ASA Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Cisco ASA

  This script performs SNMP based detection of Cisco ASA.");

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

if ("Cisco Adaptive Security Appliance" >< sysdesc) {
  version = "unknown";
  model = "unknown";

  vers = eregmatch(pattern: "Cisco Adaptive Security Appliance Version ([^ \r\n]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "cisco_asa/version", value: version);
  }

  mod = snmp_get(port: port, oid: '1.3.6.1.2.1.47.1.1.1.1.13.1');
  if(!isnull(mod))
  {
    model = str_replace(string: mod, find: '"', replace: "");
    set_kb_item(name: "cisco_asa/model", value: model);
  }

  set_kb_item(name: "cisco_asa/detected", value: TRUE);

  # For the application
  cpe = build_cpe(value: version, exp: "^([0-9.()]+)", base: "cpe:/a:cisco:asa:");
  if (!cpe)
    cpe = 'cpe:/a:cisco:asa';

  # For the OS
  cpe2 = build_cpe(value: version, exp: "^([0-9.()]+)", base: "cpe:/o:cisco:adaptive_security_appliance_software:");
  if (!cpe2)
    cpe2 = 'cpe:/o:cisco:adaptive_security_appliance_software';

  register_product(cpe: cpe, location:port + "/udp", proto:"udp", service:"snmp" );
  register_and_report_os(os: "Cisco ASA", cpe: cpe2, banner_type: "SNMP sysdesc", banner: sysdesc, port: port,
                         proto: "udp", desc: "Cisco ASA Detection (SNMP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Cisco ASA", version: version, install: "161/udp", cpe: cpe,
                                           concluded: sysdesc, extra: "Model: " + model),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
