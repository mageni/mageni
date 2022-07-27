###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sg3xx_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Small Business 300 Series Managed Switch SNMP Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.105587");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-14 14:24:09 +0200 (Mon, 14 Oct 2013)");
  script_name('Cisco Small Business 300 Series Managed Switch SNMP Detection');
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco Small Business 300 Series
Managed Switch.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port = get_snmp_port(default:161);

if (!sysdesc = get_snmp_sysdesc(port:port))
  exit(0);

if (sysdesc !~ '^S(G|F)3[0-9]+.*Managed Switch$')
  exit(0);

set_kb_item( name:'cisco/300_series_managed_switch/detected', value:TRUE );

mod = eregmatch(pattern: '^(S[GF]3[^ ]+)', string: sysdesc);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: 'cisco/300_series_managed_switch/model', value: model);
}

cpe = 'cpe:/o:cisco:300_series_managed_switch_firmware';
version = 'unknown';

oid = "1.3.6.1.2.1.47.1.1.1.1.10.67108992";
vers = snmp_get(port: port, oid: oid);

version = "unknown";

if (vers =~ '^[0-9]+\\.') {
  set_kb_item(name: 'cisco/300_series_managed_switch/version', value: vers);
  version = vers;
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:300_series_managed_switch_firmware:");
if(!cpe)
  cpe = "cpe:/o:cisco:300_series_managed_switch_firmware";

register_product(cpe: cpe, location: port + "/udp", service: "snmp", proto: "udp", port: port );

log_message(data: build_detection_report(app: "Cisco Small Business 300 Series Managed Switch " + model,
                                         version: version, install: port + '/udp', cpe: cpe),
            port: port, proto: "udp");

exit(0);
