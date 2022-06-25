###############################################################################
# OpenVAS Vulnerability Test
#
# Identd scan
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.14674");
  script_version("2019-05-24T07:46:22+0000");
  script_tag(name:"last_modification", value:"2019-05-24 07:46:22 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Identification Protocol (ident) Service Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "slident.nasl", "secpod_open_tcp_ports.nasl");
  script_require_ports("Services/auth", 113);
  script_mandatory_keys("TCP/PORTS");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc1413");

  script_tag(name:"summary", value:"This plugin tries to detect services supporting the
  Identification Protocol (ident) and determines which user is running each service exposed
  by the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

ports = get_all_tcp_ports_list();
if( ! ports )
  exit( 0 );

list = get_ports_for_service( default_list:make_list( 113 ), proto:"auth" );
foreach iport( list ) {
  if( get_port_state( iport ) && ! get_kb_item( "fake_identd/" + iport ) ) {
    isoc = open_sock_tcp( iport );
    if( isoc )
      break;
  }
}

if( ! isoc )
  exit( 0 );

identd_n = 0;
os_reported = FALSE;

# nb: Try several times, as some ident daemons limit the throughput of answers?!
for( i = 1; i <= 6 && ! isnull( ports ); i++ ) {

  prev_ident_n = identd_n;
  j = 0;

  foreach port( ports ) {
    if( get_port_state( port ) && ! get_kb_item( "ident/tcp" + port ) ) {
      soc = open_sock_tcp( port );
      if( soc ) {
        req = strcat( port, ',', get_source_port( soc ), '\r\n' );
        if( send( socket:isoc, data:req ) <= 0 ) {
          # In case identd does not allow several requests in a raw
          close( isoc );
          isoc = open_sock_tcp( iport );
          if( ! isoc ) {
            close( soc );
            exit( 0 );
          }
          send( socket:isoc, data:req );
        }

        res = recv_line( socket:isoc, length:1024 );
        res = chomp( res );

        # nb: Some banners are coming in like e.g. (including the newline)
        # 113,55972
        #  : USERID : iOS : dragon2
        # In this case we're receiving the second line as well.
        if( res =~ "^[0-9]+ ?, ?[0-9]+" && "USERID" >!< res ) {
          res2 = recv_line( socket:isoc, length:1024 );
          res2 = chomp( res2 );
          if( res2 )
            res += res2;
        }

        if( res && "USERID" >< res ) {
          _res = split( res , sep:":", keep:FALSE );
          if( max_index( _res ) > 2 ) {

            os = chomp( _res[2] );
            os = ereg_replace( string:os, pattern:"^(\s+)", replace:"" );
            id = chomp( _res[3] );
            id = ereg_replace( string:id, pattern:"^(\s+)", replace:"" );
            # e.g.
            # 53,35089:USERID:UNIX:pdns
            # 113 , 60954 : USERID : 20 : oidentd
            # 113,60662 : USERID : WIN32 :<spaces>
            # see also https://tools.ietf.org/html/rfc1413
            if( "USERID" >< _res[1] && strlen( id ) && strlen( id ) < 30 ) {
              identd_n++;
              set_kb_item( name:"ident/tcp/" + port, value:id );
              report  = "identd reveals that this service is running as user '" + id + "'.";
              report += ' Response:\n\n' + res;
              log_message( port:port, data:report );
            }

            # nb: Some ident services are just reporting a number
            if( os && ! egrep( string:os, pattern:"^[0-9]+$" ) && ! os_reported ) {
              set_kb_item( name:"ident/os_banner/available", value:TRUE );
              os_reported = TRUE;
              # nb: Using replace_kb_item here to avoid having multiple OS banners for different services saved within the kb if e.g. the process owner or source port was changed.
              replace_kb_item( name:"ident/" + iport + "/os_banner/full", value:res );
              replace_kb_item( name:"ident/" + iport + "/os_banner/os_only", value:os );
            }
          } else {
            bad[j++] = port;
          }
        } else {
          bad[j++] = port;
        }
        close( soc );
      }
    }
  }

  # Exit if we are running in circles
  if( prev_ident_n == identd_n )
    break;

  ports = NULL;
  foreach j( bad )
    ports[j] = j;
  bad = NULL;
}

close( isoc );
set_kb_item( name:"Host/ident_scanned", value:TRUE );

if( identd_n > 0 ) {
  log_message( port:iport, data:"A service supporting the Identification Protocol (ident) seems to be running on this port." );
  register_service( port:iport, proto:"auth", message:"A service supporting the Identification Protocol (ident) seems to be running on this port." );
}

exit( 0 );