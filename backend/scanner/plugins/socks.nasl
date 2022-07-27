###############################################################################
# OpenVAS Vulnerability Test
# $Id: socks.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# SOCKS server detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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

# Socks4 protocol is described on
# http://www.socks.nec.com/protocol/socks4.protocol
# Socks4a extension is described on
# http://www.socks.nec.com/protocol/socks4a.protocol
# Socks5 is defined by those RFC:
# RFC1928 SOCKS Protocol Version 5
# RFC1929 Username/Password Authentication for SOCKS V5
# RFC1961 GSS-API Authentication Method for SOCKS Version 5

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11865");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SOCKS server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/socks4", "Services/socks5", "Services/unknown", 1080);
  script_dependencies("find_service.nasl", "find_service2.nasl");

  script_tag(name:"summary", value:"A SOCKS server is running on this host");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc"); # make_list_unique

function mark_socks_proxy( port, ver, ext_ip, authm ) {

  local_var rep;

  #display("ver=", ver, "\text_ip=", ext_ip, "\tauth=", authm, "\n");

  register_service( port:port, proto:"socks" + ver );
  rep = strcat( 'A SOCKS', ver, ' server is running on this port\n' );
  if( ext_ip ) {
    rep = strcat( rep, 'Its external interface address is ', ext_ip, '\n' );
  } else {
    rep = strcat( rep, 'We could not determine its external interface address\n' );
  }

  if( ! isnull( authm ) ) {

    set_kb_item( name:"socks" + ver + "/auth/" + port, value:authm );
    if( authm == 0 )
      rep = strcat( rep, 'It does not require authentication, or does not implement it.\n' );
    else if( authm == 1 )
      rep = strcat( rep, 'It prefers the username/password authentication.\n' );
    else if( authm == 2 )
      rep = strcat( rep, 'It prefers the GSS API authentication.\n' );
    else if( authm == 255 )
      rep = strcat( rep, 'It rejected all standard authentication methods (none, password, GSS API).\n' );
    else
      rep = strcat( rep, 'It prefers the unknown ', authm, ' authentication method (bug?)\n' );
  }
  log_message( port:port, data:rep );
}

function test_socks( port ) {

  # No need to declare local vars in this function
  soc = open_sock_tcp( port );
  if( ! soc ) return;

  # SOCKS4 request:
  # 1	Version number (4)
  # 1	Command (1: connect / 2: bind)
  # 2	Port
  # 4	Address
  # Var	UserID
  # 1	zero (0)
  #
  # Bind: (local) port = 65535; expected remote address = 10.10.10.10

  req4 = raw_string( 4, 2, 255, 255, 10, 10, 10, 10 );
  req4 += "root";
  req4 += raw_string( 0 );
  send( socket:soc, data:req4 );
  data = recv( socket:soc, length:8 );
  close(soc);

  if( strlen( data ) == 8 ) {

    # SOCKS4 answer:
    # 1	version (0)
    # 1	code (90 -> 92)
    # 2	port (or 0)
    # 4	IP (or 0)
    if( ord( data[0] ) == 0 && ord( data[1] ) >= 90 && ord( data[1] ) <= 93 ) {
      # Looks like a SOCKS4 server
      if( ord( data[1] ) == 90 ) {
        ext = strcat( ord( data[4] ), '.', ord( data[5] ), '.', ord( data[6] ), '.', ord( data[7] ) );
      } else {
        exp = NULL;
      }
      set_kb_item( name:"socks4/detected", value:TRUE );
      mark_socks_proxy( port:port, ver:4, ext_ip:ext );
    }
  }

  #  SOCKS5 connection:
  #  1	Version number (5)
  #  1	# of auth methods
  #  Var	Array of methods:
  #	1	Method number:	0: no auth
  #				1: GSSAPI
  #				2: password
  #				3-7F: IANA reserved,
  #				80-FE: user reserved
  #				FF: no method
  # We should announce at least GSS API to be RFC conformant.
  #
  # The server answers:
  # 1	Version
  # 1	Chosen method (or FF if failure)

  soc = open_sock_tcp( port );
  if( ! soc ) return;

  req5 = raw_string( 5, 3, 0, 1, 2 );
  send( socket:soc, data:req5 );
  data = recv( socket:soc, length:2 );
  if( strlen( data ) == 2 ) {
    if( ord( data[0] ) == 5 && ( ord( data[1] ) <= 2 || ord( data[1] == 255 ) ) ) {
      authm = ord( data[1] );
      # Really looks like a SOCKS5 server
      req5 = raw_string( 5, 2, 0, 1, 10, 10, 10, 10, 255, 255 ); # BIND
      send( socket:soc, data:req5 );
      data = recv( socket:soc, length:10 );
      if( strlen( data ) < 4 || ord( data[1] ) != 0 || ord( data[3] ) != 1 ) {
        ext = NULL;
      } else {
        ext = strcat( ord( data[4]), '.', ord( data[5] ), '.', ord( data[6] ), '.', ord( data[7] ) );
      }
      set_kb_item( name:"socks5/detected", value:TRUE );
      mark_socks_proxy( port:port, ver:5, ext_ip:ext, authm:authm );
    }
  }
  close( soc );
}

s = get_kb_list( "Services/socks4" );
if( ! isnull( s ) )
  s = make_list( s );
else
  s = make_list();

s2 = get_kb_list( "Services/socks5" );
if( ! isnull( s2 ) )
  s2 = make_list( s2 );
else
  s2 = make_list();

s3 = get_unknown_port_list( default:1080 );
if( ! isnull( s3 ) )
  s3 = make_list( s3 );
else
  s3 = make_list();

ports = make_list_unique( 1080, s, s2,  s3 );

foreach port( ports ) {
  if( get_port_state( port ) && service_is_unknown( port:port ) ) {
    test_socks( port:port );
  }
}

exit( 0 );