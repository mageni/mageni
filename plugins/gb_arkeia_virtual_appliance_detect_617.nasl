###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arkeia_virtual_appliance_detect_617.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Arkeia Arkaiad Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107040");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-08-11 13:16:06 +0200 (Thu, 11 Aug 2016)");
  script_name("Arkeia Arkaiad Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/unknown", 617);

  script_tag(name:"summary", value:"The script sends a connection request to the Arkeia Appliance and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

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

function arkeiad_recv( soc )
{
    r = recv( socket:soc, length: 8 );

    if( ! r || strlen( r ) < 8 ) return;
    len = ord( r[7] );
    if( ! len || len < 1 ) return r;
    r += recv( socket:soc, length:len );

    return r;
}

appPort = get_unknown_port( default:617 );

soc = open_sock_tcp( appPort );
if ( ! soc ) exit ( 0 );

req = raw_string(
0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x02, 0x74,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x74, 0x02, 0xa8, 0xc0,
0x41, 0x52, 0x4b, 0x41,0x44, 0x4d, 0x49, 0x4e, 		#"ARKADMIN"
0x00,
0x72, 0x6f, 0x6f,0x74, 0x00, 0x72, 0x6f, 0x6f, 0x74,	#"root"
0x00, 0x00, 0x00,
0x34, 0x2e, 0x33, 0x2e, 0x30, 0x2d, 0x31, 		# version
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00 );

send( socket:soc, data:req );
res = arkeiad_recv( soc:soc );

if( raw_string(0x00, 0x60, 0x00, 0x04)  >!< res ) exit(0);

req = raw_string(
0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00 );

send( socket:soc, data:req );
res2 = arkeiad_recv( soc:soc );

if ( raw_string(0x00, 0x60, 0x00, 0x04)  >!< res2 ) exit(0);

req = raw_string (
0x00, 0x61, 0x00, 0x04, 0x00, 0x01, 0x00, 0x11,
0x00, 0x00, 0x31, 0x00,
0x45, 0x4e, 						# Language
0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00 );

send( socket:soc, data:req );
res3 = arkeiad_recv( soc:soc );

if ( raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 ) >!< res3 ) exit(0);

req = raw_string (
0x00, 0x62, 0x00, 0x01, 0x00, 0x00, 0x00, 0x26,
0x41, 0x52, 0x4b, 0x41, 0x44, 0x4d, 0x49, 0x4e,
0x5f, 0x47, 0x45, 0x54, 0x5f, 0x43, 0x4c, 0x49,
0x45, 0x4e, 0x54, 0x5f, 0x49, 0x4e, 0x46, 0x4f, 	# "ARKADMIN_GET_CLIENT_INFO FUNCTION
0x00, 0x32, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );

send( socket: soc, data:req );
res4 = arkeiad_recv( soc:soc );

if (raw_string( 0x00, 0x43, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 ) >!< res4 ) exit(0);

req = raw_string (
0x00, 0x63, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12,
0x30, 0x00, 0x31, 0x00, 0x32, 0x38, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00 );

send( socket: soc, data:req );
while( TRUE )
{
        x = arkeiad_recv( soc:soc );

        if( ! x  ) break;
        res5 += x;

        if( x[0] == raw_string( 0x00 ) && x[1] == raw_string(0x69 ) )  break;

}

close (soc);
ArkVer = 'unknown';

res5 = parse_result( data:res5);

if( "ARKADMIN_GET_CLIENT_INFO" >!< res5 ) exit( 0 );

Ver = eregmatch (string: res5, pattern: 'IVERSION WD Arkeia ([0-9.]+)');

cpe = 'cpe:/a:arkeia:western_digital_arkeia';

if( ! isnull( Ver[1] ) )
{
  ArkVer = Ver[1];
  cpe += ':' + ArkVer;
}

set_kb_item(name: "Arkeia/arkeiad/version", value: ArkVer);
register_service( port:appPort, proto:"arkeiad");

register_product( cpe:cpe, location:appPort + '/tcp', port: appPort, service: 'arkeiad' );
log_message(data: build_detection_report(app:"Arkeia Arkeiad",
                                         version:ArkVer,
                                         install:appPort + '/tcp',
                                         cpe:cpe,
                                         concluded: ArkVer),
                                         port:appPort);

exit(0);

