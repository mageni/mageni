###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cnpilot_snmp_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# On Cambium Networks cnPilot Detect (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.140186");
  script_version("$Revision: 8078 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-03-14 17:03:28 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detect (SNMP)");

  script_tag(name:"summary", value:"Detection of Cambium Networks cnPilot.

This script performs SNMP based detection of Cambium Networks cnPilot.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if( sysdesc !~ '^cnPilot' ) exit( 0 );

set_kb_item( name:"cnPilot/detected", value:TRUE );

version = "unknown";
cpe = 'cpe:/o:cambium_networks:cnpilot_series_firmware';
app = 'cnPilot ';

# cnPilot R201P 4.2.3-R4
# cnPilot R201 4.2.3-R4
# cnPilot R200 4.0-R2
# cnPilot R200P 4.3.1-R1

v_m = eregmatch( pattern:'cnPilot ([A-Za-z][0-9]+([A-za-z])?) ([0-9.]+(-[A-Za-z][0-9]+)?)', string:sysdesc );

if( ! isnull( v_m[1] ) )
{
  model = v_m[1];
  set_kb_item( name:"cnPilot/model", value:model );
  app += '(' + model + ')';
}

if( ! isnull( v_m[3] ) )
{
  version = v_m[3];
  set_kb_item( name:"cnPilot/version", value:version );
  cpe += ':' + version;
}

register_product( cpe:cpe, location:port + "/udp", port:port, service:"snmp", proto:"udp" );

report = build_detection_report( app:app, version:version, install:port + "/udp", cpe:cpe, concluded:sysdesc );

log_message( port:port, proto:"udp", data:report );

exit(0);
