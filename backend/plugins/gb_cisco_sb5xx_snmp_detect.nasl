###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sb5xx_snmp_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Cisco Small Business 500 Series Stackable Managed Switches SNMP Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812003");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-03 16:38:14 +0530 (Tue, 03 Oct 2017)");
  script_name('Cisco Small Business 500 Series Stackable Managed Switches SNMP Detection');

  script_tag(name:"summary", value:"This script performs SNMP based detection of
  Cisco Small Business 500 Series Stackable Managed Switches.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

cisPort = get_snmp_port(default: 161);

if (!sysdesc = get_snmp_sysdesc(port:cisPort))
  exit(0);

##SG500-52 52-Port Gigabit Stackable Managed Switch
if (sysdesc !~ '^S(G|F)5[0-9]+.*Stackable Managed Switch$')
  exit(0);

set_kb_item(name: 'cisco/500_series_stackable_managed_switch/detected', value: TRUE);

mod = eregmatch(pattern: '^(S[GF]5[^ ]+)', string: sysdesc);
if (!isnull(mod[1])) {
  model = mod[1];
  set_kb_item(name: 'cisco/500_series_stackable_managed_switch/model', value: model);
}

oid = "1.3.6.1.2.1.47.1.1.1.1.10.67108992";
vers = snmp_get(port: cisPort, oid: oid);

version = "unknown";

if (vers =~ '^[0-9]+\\.') {
  set_kb_item( name:'cisco/500_series_stackable_managed_switch/version', value:vers );
  version = vers;
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                base: "cpe:/o:cisco:500_series_stackable_managed_switch_firmware:");
if(!cpe)
  cpe = "cpe:/o:cisco:500_series_stackable_managed_switch_firmware";

register_product(cpe: cpe, location: cisPort + "/udp", service: "snmp", proto: "udp", port: cisPort);

log_message(data: build_detection_report(app: "Cisco Small Business 500 Series Stackable Managed Switch " + model,
                                         version: version, install: cisPort + '/udp', cpe:cpe),
                                         proto: "udp", port: cisPort);

exit(0);
