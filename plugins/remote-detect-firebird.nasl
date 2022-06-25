###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-firebird.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# This script ensure that a Firebird/InterBase database server is installed and running
#
# Authors:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80004");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Firebird/InterBase database Server service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service6.nasl");
  script_require_ports("Services/unknown", 3050);

  script_tag(name:"summary", value:"The remote host is running the Firebird/InterBase database Server.
  Firebird is a RDBMS offering many ANSI SQL:2003 features.

  It runs on Linux, Windows, and a variety of Unix platforms
  and Started as a fork of Borland's open source release of InterBase");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);

}

include("misc_func.inc");
include("host_details.inc");
include("byte_func.inc");

function check_firebird_response( res ) {

  local_var res, status;

  if( isnull( res ) || strlen( res ) != 16 ) {
    return FALSE;
  }

  # Protocol version 10 supported
  if( "030000000a0000000100000003" >< hexstr( res ) ) {
    status['installed'] = TRUE;
    status['proto_ver'] = 10;
    return status;
  # Protocol version 8 supported
  } else if( "03000000080000000100000003" >< hexstr( res ) ) {
    status['installed'] = TRUE;
    status['proto_ver'] = 8;
    return status;
  # Not installed or unknown protocol version
  } else {
    return FALSE;
  }
}

port = get_unknown_port( default:3050 );

# forge the firebird negotiation protocol for < 2.5
# This was initially used in this NVT in 2008 so keep in here for now
firebird_auth_packet1 = raw_string(
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x02,0x00,
0x00,0x00,0x24,0x00,0x00,0x00,0x1c,0x2f,0x6f,0x70,0x74,0x2f,0x66,
0x69,0x72,0x65,0x62,0x69,0x72,0x64,0x2f,0x62,0x69,0x6e,0x2f,0x6c,
0x65,0x67,0x69,0x6f,0x6e,0x2e,0x66,0x64,0x62,0x00,0x00,0x00,0x02,
0x00,0x00,0x00,0x17,0x01,0x04,0x72,0x6f,0x6f,0x74,0x04,0x09,0x63,
0x68,0x72,0x69,0x73,0x74,0x69,0x61,0x6e,0x05,0x04,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,
0x00,0x00,0x04);

# forge the firebird negotiation protocol for 2.5
# from a wireshark dump of a connection with a firebird client
# See also https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-gdsdb.c
file        = "openvas.fdb";
file_length = strlen( file );
if( file_length % 4 != 0 )
  file_pad = crap( data:raw_string( 0x00 ), length:4 - ( file_length & 3 ) );

user        = "openvas";
user_length = strlen( user );
host        = this_host_name();
host_length = strlen( host );
u_h_length  = user_length + host_length;

if( ( u_h_length + 2 ) % 4 != 0 )
  u_h_pad = crap( data:raw_string( 0x00 ), length:4 - ( ( u_h_length + 2 ) & 3 ) );

firebird_auth_packet2 =
  mkdword( 1 ) +              # Opcode: Connect (1)
  mkdword( 19 ) +             # Operation: Attach (19)
  mkdword( 2 ) +              # Version: 2
  mkdword( 36 ) +             # Client Architecture: Linux (36)
  mkdword( file_length ) +
  file +
  file_pad +
  mkdword( 2 ) +              # Version option count: 2 -> See below
  mkdword( u_h_length + 6 ) +
  raw_string( 0x01 ) +        # Currently unknown
  raw_string( user_length ) +
  user +
  raw_string( 0x20 ) +        # Currently unknown
  raw_string( host_length ) +
  host +
  raw_string( 0x06, 0x00 ) +  # Currently unknown
  u_h_pad +
  # Preferred version 1
  mkdword( 8 ) +              # Version: 8
  mkdword( 1 ) +              # Architecture: Generic (1)
  mkdword( 2 ) +              # Minimum type: 2
  mkdword( 3 ) +              # Maximum type: 3
  mkdword( 2 ) +              # Preference weight: 2
  # Preferred version 2
  mkdword( 10 ) +             # Version: 10
  mkdword( 1 )  +             # Architecture: Generic (1)
  mkdword( 2 )  +             # Minimum type: 2
  mkdword( 3 )  +             # Maximum type: 3
  mkdword( 4 );               # Preference weight: 4

# TODO: 3.0
# https://www.firebirdsql.org/file/documentation/release_notes/html/en/3_0/rnfb30-security-new-authentication.html

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:firebird_auth_packet1 );
res = recv( socket:soc, length:1024 );
close( soc );

if( status = check_firebird_response( res:res ) ) {
  installed = status['installed'];
  proto_ver = status['proto_ver'];
} else {
  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  send( socket:soc, data:firebird_auth_packet2 );
  res = recv( socket:soc, length:1024 );
  close( soc );
  if( status = check_firebird_response( res:res ) ) {
    installed = status['installed'];
    proto_ver = status['proto_ver'];
  }
}

if( installed ) {

  set_kb_item( name:"firebird_db/installed", value:TRUE );
  register_service( port:port, proto:"gds_db" );

  install = port + "/tcp";
  cpe     = "cpe:/a:firebirdsql:firebird";
  extra   = "Supported protocol version: " + proto_ver;

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Firebird/Interbase database",
                                            install:install,
                                            extra:extra,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );