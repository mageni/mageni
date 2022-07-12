###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_meinberg_lantime_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Meinberg LANTIME Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106109");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-24 14:37:30 +0700 (Fri, 24 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Meinberg LANTIME Detection");

  script_tag(name:"summary", value:"Detection of Meinberg NTP Timeserver LANTIME

This script performs SNMP based detection of Meinberg NTP Timeserver LANTIME.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name:"URL", value:"https://www.meinbergglobal.com/english/products/ntp-time-server.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if ("Meinberg LANTIME" >< sysdesc) {
  mo = eregmatch(pattern: "LANTIME ([A-Z0-9//]+)", string: sysdesc);
  if (isnull(mo[1]))
    exit(0);

  model = mo[1];

  version = "unknown";
  ver = eregmatch(pattern: "V([0-9.]+)", string: sysdesc);
  if (!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name: "meinberg_lantime/detected", value: TRUE);
  set_kb_item(name: "meinberg_lantime/model", value: model);

  if (version != "unknown")
    set_kb_item(name: "meinberg_lantime/version", value: version);

  cpe_model = eregmatch(pattern: "[A-Z0-9]+", string: model);
  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:meinberg:lantime_" + tolower(cpe_model[0]) + ":");
  if (isnull(cpe))
    cpe = "cpe:/a:meinberg:lantime_" + tolower(cpe_model[0]);

  register_product(cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp");

  log_message(data: build_detection_report(app: "Meinberg LANTIME " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: 'udp');
}

exit(0);
