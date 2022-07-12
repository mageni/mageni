###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arista_eos_snmp_detect.nasl 7236 2017-09-22 14:59:19Z cfischer $
#
# Arista EOS Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106494");
  script_version("$Revision: 7236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-22 16:59:19 +0200 (Fri, 22 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-01-05 14:24:16 +0700 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Arista EOS Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Arista EOS devices

This script performs SNMP based detection of Arista EOS devices.");

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

if ("Arista Networks EOS" >< sysdesc) {
  model = "unknown";
  version = "unknown";

  mod = eregmatch(pattern: "running on an Arista Networks ([0-9A-Z-]+)", string: sysdesc);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "arista/eos/model", value: model);
  }

  vers = eregmatch(pattern: "EOS version ([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "arista/eos/version", value: version);
  }

  set_kb_item(name: "arista/eos/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:arista:eos:");
  if (!cpe)
    cpe = 'cpe:/o:arista:eos';

  register_product(cpe: cpe, port: port, service: "snmp", proto: "udp");
  register_and_report_os(os: "Arista EOS", cpe: cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port,
                         proto: "udp", desc: "Arista EOS Detection (SNMP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Arista EOS", version: version, install: "161/udp", cpe: cpe,
                                           concluded: sysdesc, extra: "Model: " + model),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
