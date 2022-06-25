###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_detect_giop.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# IBM WebSphere Application Server Detection Detection (GIOP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105834");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-29 15:04:09 +0200 (Fri, 29 Jul 2016)");
  script_name("IBM WebSphere Application Server Detection (GIOP)");

  script_tag(name:"summary", value:"The script sends a GIOP (General Inter-ORB Protocol) connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/giop", 9100, 9900);
  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");

function parse_result( data )
{
  if( strlen( data ) < 8 ) return FALSE;

  for( v = 0; v < strlen( data ); v++ )
    if( isprint( c:data[v] ) )
      tmp += data[v];
    else
      tmp += ' ';

  return tmp;
}

port = get_kb_item("Services/giop");
if( ! port ) port = 9100;

if( ! get_port_state( port ) ) exit( 0 );

# 9100 which might be a PJL port which is printing
# everything sent to it so exit for such a port here
if( is_fragile_port( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

giop_req = 'GIOP' + raw_string(
0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xe4,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,
0x00,0x00,0x00,0xa0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x49,0x44,0x4c,0x3a,
0x6f,0x6d,0x67,0x2e,0x6f,0x72,0x67,0x2f,0x53,0x65,0x6e,0x64,0x69,0x6e,0x67,0x43,
0x6f,0x6e,0x74,0x65,0x78,0x74,0x2f,0x43,0x6f,0x64,0x65,0x42,0x61,0x73,0x65,0x3a,
0x31,0x2e,0x30,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,
0x00,0x01,0x02,0x00,0x00,0x00,0x00,0x0e,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,
0x32,0x2e,0x31,0x33,0x36,0x00,0x04,0x79,0x00,0x00,0x00,0x19,0xaf,0xab,0xcb,0x00,
0x00,0x00,0x00,0x02,0x93,0xbe,0x05,0x06,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x02,
0x05,0x01,0x00,0x01,0x00,0x01,0x00,0x20,0x00,0x01,0x01,0x09,0x00,0x00,0x00,0x01,
0x00,0x01,0x01,0x00,0x4e,0x45,0x4f,0x00,0x00,0x00,0x00,0x02,0x00,0x0a,0x00,0x00,
0x00,0x00,0x00,0x05,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x49,0x4e,0x49,0x54,
0x00,0x00,0x00,0x04,0x67,0x65,0x74,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
0x4e,0x61,0x6d,0x65,0x53,0x65,0x72,0x76,0x69,0x63,0x65,0x00);

send( socket:soc, data:giop_req );
data = recv( socket:soc , length:4096 );

close( soc );

if( "WebSphere" >!< data ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:ibm:websphere_application_server';

set_kb_item(name:"ibm_websphere_application_server/installed", value:TRUE );

data = parse_result( data:data );

version = eregmatch( pattern:"IBM WebSphere Application Server( Network Deployment)?\s*([0-9.]+[^ ]+)", string:data );

if( ! isnull( version[2] ) )
{
  vers = version[2];
  cpe += ':' + version[2];
}

register_product( cpe:cpe, location:port +'/tcp', port:port, service:'giop' );

report = build_detection_report( app:'IBM WebSphere Application Server', version:vers, install:port +'/tcp', cpe:cpe, concluded:version[0] );
log_message( port:port, data:report );

exit( 0 );

