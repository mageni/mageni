###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cradlepoint_router_snmp_detect.nasl 12684 2018-12-06 10:51:02Z asteins $
#
# Cradlepoint Routers Detection (SNMP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112449");
  script_version("$Revision: 12684 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 11:51:02 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-06 11:16:11 +0100 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cradlepoint Routers Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cradlepoint routers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port( default:161 );
sysdesc = get_snmp_sysdesc( port:port );
if( ! sysdesc || ( "Cradlepoint" >!< sysdesc ) ) exit( 0 );

set_kb_item( name:"cradlepoint/router/detected", value:TRUE );
set_kb_item( name:"cradlepoint/router/snmp/detected", value:TRUE );
set_kb_item( name:"cradlepoint/router/snmp/port", value:port );

model      = "unknown";
fw_version = "unknown";

# "Cradlepoint IBR650LPE, Firmware Version 6.1.0.0d93fc0"
model_nd_fw = eregmatch( pattern:"Cradlepoint ([A-Z0-9]+), Firmware Version ([0-9.]+)", string:sysdesc, icase:TRUE );
if( ! isnull( model_nd_fw[1] ) ) model = model_nd_fw[1];
if( ! isnull( model_nd_fw[2] ) ) fw_version = model_nd_fw[2];
# Remove redundant information
fw_version = ereg_replace( pattern:"\.$", string:fw_version, replace:"" );

set_kb_item( name:"cradlepoint/router/snmp/" + port + "/model", value:model );
set_kb_item( name:"cradlepoint/router/snmp/" + port + "/fw_version", value:fw_version );
set_kb_item( name:"cradlepoint/router/snmp/" + port + "/concluded", value:sysdesc );

exit( 0 );
