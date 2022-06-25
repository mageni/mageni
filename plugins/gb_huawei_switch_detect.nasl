###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_switch_detect.nasl 13258 2019-01-24 08:31:20Z ckuersteiner $
#
# Huawei Switch Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106156");
  script_version("$Revision: 13258 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 09:31:20 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2016-07-29 09:30:37 +0700 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei Switch Detection");

  script_tag(name:"summary", value:"Detection of Huawei Switches

This script performs SNMP based detection of Huawei Switches.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"http://e.huawei.com/en/products/enterprise-networking/switches");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if ("Huawei Versatile Routing Platform Software" >< sysdesc) {
  mo = eregmatch(pattern: "Quidway (S[0-9]+([A-Z-]+)?)", string: sysdesc);
  if (!isnull(mo[1]))
    model = mo[1];
  else {
    # Some switches have the model at the beginning e.g.
    # S12712
    # Huawei Versatile Routing Platform Software
    # VRP (R) Software, Version 5.170 (S12700 V200R010C00SPC600)
    if (egrep(pattern: "\(S(12700|2700|5700|6720) V", string: sysdesc)) {
      mo = eregmatch(pattern: '^([^\r\n]+)', string: sysdesc);
      if (!isnull(mo[1]))
        model = chomp(mo[1]);
      else
        exit(0);
    }
    else {
      mo = eregmatch(pattern: "\(([A-Z0-9-]+) ", string: sysdesc);
      if (!isnull(mo[1]))
        model = mo[1];
      else
        exit(0);
    }
  }

  version = "unknown";
  vers = eregmatch(pattern: "Version [0-9.]+ .*(V[0-9A-Z]+)", string: sysdesc);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "huawei_switch/detected", value: TRUE);
  set_kb_item(name: "huawei_switch/model", value: model);
  if (version != "unknown")
    set_kb_item(name: "huawei_switch/version", value: version);

  cpe = build_cpe(value: tolower(version), exp: "^(v[0-9a-z]+)", base: "cpe:/h:huawei:" + tolower(model) + ":");
  if (!cpe)
    cpe = "cpe:/h:huawei:" + tolower(model);

  register_product(cpe: cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");

  log_message(data: build_detection_report(app: "Huawei Switch " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: "udp");
  exit(0);
}

exit(0);
