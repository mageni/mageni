###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vicon_industries_network_camera_detect_snmp.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# Vicon Industries Network Camera Detection (SNMP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107333");
  script_version("$Revision: 10905 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-07-23 12:16:49 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vicon Industries Network Camera Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Vicon Industries Network Cameras.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");

port = get_snmp_port( default:161 );
if( ! sysdesc = get_snmp_sysdesc( port:port ) ) exit ( 0 );

if( sysdesc =~ "IQinVision" ) {

  set_kb_item( name:"vicon_industries/network_camera/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/snmp/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/snmp/port", value:port );

  version = "unknown";
  type    = "unknown";

  vers = eregmatch( pattern:"(V|B|Version )(V[0-9.]+)", string:sysdesc, icase:FALSE );
  if( vers[2] ) version = vers[2];

  type = eregmatch( pattern:"IQ(eye)?([0578ADMPR])", string:sysdesc, icase:FALSE );

  type_list['0'] = "3 Series / 4 Series";
  type_list['5'] = "5 Series";
  type_list['7'] = "7 Series";
  type_list['8'] = "Sentinel Series";
  type_list['9'] = "9 Series";
  type_list['A'] = "Alliance-pro";
  type_list['D'] = "Alliance-mini";
  type_list['M'] = "Alliance-mx";
  type_list['P'] = "PTZ";
  type_list['R'] = "R5 Series";

  if( type_list[type[2]] ) {
    type = type_list[type[2]];

  } else {
    type = "unknown";
    }

  set_kb_item( name:"vicon_industries/network_camera/snmp/" + port + "/type", value:type );
  set_kb_item( name:"vicon_industries/network_camera/snmp/" + port + "/version", value:version );
  set_kb_item( name:"vicon_industries/network_camera/snmp/" + port + "/concluded", value:sysdesc);
}

exit( 0 );
