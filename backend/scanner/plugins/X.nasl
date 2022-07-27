###############################################################################
# OpenVAS Vulnerability Test
# $Id: X.nasl 10123 2018-06-07 13:22:15Z cfischer $
#
# X Server Detection
#
# Authors:
# John Jackson <jjackson@attrition.org>
# Pavel Kankovsky <kan@dcit.cz>:
# proper X11 protocol handling
# Changes by rd
#
# Copyright:
# Copyright (C) 2000 John Jackson
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

# Fri May 12 15:58:21 GMT 2000
# Test for an "open" X server
# An X server's access control is disabled (e.g. through an "xhost +" command) and
# allows anyone to connect to the server.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10407");
  script_version("$Revision: 10123 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 15:22:15 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("X Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2000 John Jackson");
  script_dependencies("find_service.nasl");
  script_require_ports(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);

  script_tag(name:"summary", value:"This plugin detects X Window servers.

  X11 is a client - server protocol. Basically, the server is in charge of the
  screen, and the clients connect to it and send several requests like drawing
  a window or a menu, and the server sends events back to the clients, such as
  mouse clicks, key strokes, and so on...

  An improperly configured X server will accept connections from clients from
  anywhere. This allows an attacker to make a client connect to the X server to
  record the keystrokes of the user, which may contain sensitive information,
  such as account passwords.
  This can be prevented by using xauth, MIT cookies, or preventing
  the X server from listening on TCP (a Unix sock is used for local
  connections)");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

function riptext( data, begin, length ) {

  local_var data, begin, length, count, end, text;

  count = begin;
  end = begin + length - 1;
  if( end >= strlen( data ) )
    end = strlen( data ) - 1;
  text = "";

  for( count = begin; count <= end; count++ ) {
    text = string( text + data[count] );
  }
  return text;
}

####   ##   # ###
# # # #  #  # #  #
# # #  ## # # #  #

#
# The format of client request
#  CARD8    byteOrder (66 'B'=MSB, 108 'l'=LSB)
#  BYTE     padding
#  CARD16   majorVersion, minorVersion
#  CARD16   nBytesAuthProto  (authorization protocol)
#  CARD16   nBytesAuthString (authorization data)
#  CARD     padding
#  STRING8  authProto
#  STRING8  authString
#
# The format of server response:
#  CARD8    success (0=Failed, 1=Success, 2=Authenticate)
#  BYTE     lengthReason (unused if success==1)
#  CARD16   majorVersion, minorVersion (unused if success==2)
#  CARD16   length (of additional data)
#  STRING8  reason (for success==0 or success==1)
#
# CARD16 values are endian-sensitive; endianness is determined by
# the first byte sent by a client
#

# hmm....it might look like a good idea to raise the higher limit to test
# connections forwarded by OpenSSH but it is pointless because OpenSSH
# does not process connections without a cookie--everything you'll get
# will be a stale connection

xwininfo = raw_string(108,0,11,0,0,0,0,0,0,0,0,0);
# change the xwininfo bytes above to force servers to send a version mismatch

for( port = 6000; port < 6010; port++ ) {

  if( ! get_port_state( port ) ) continue;
  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  extra = "";
  send( socket:soc, data:xwininfo );
  res = recv( socket:soc, length:32 );
  close( soc );
  if( res && strlen(res) >= 8 ) {

    result = ord( res[0] );

    if( result == 0 ) { # Failed
      major = ord( res[2] ) + 256 * ord( res[3] );
      minor = ord( res[4] ) + 256 * ord( res[5] );
      ver = strcat( major, ".", minor );
      set_kb_item( name:"X11/" + port + "/version", value:ver );

      textres = riptext( data:res, begin:8, length:ord( res[1] ) );
      if( textres ) {
        set_kb_item( name:"X11/" + port + "/answer", value:textres );
        extra = "Server answered with: " + textres;
      }
      set_kb_item( name:"X11/" + port + "/open", value:FALSE );

      register_service( port:port, proto:"X11" );
      register_and_report_cpe( app:"X Windows Server", ver:ver, base:"cpe:/a:x.org:x11:", expr:"^([0-9.]+([a-z0-9]+)?)", regPort:port, insloc:port + "/tcp", extra:"Server answered with: " + textres );
    }

    if( result == 1 ) { # Success
      major = ord( res[2] ) + 256 * ord( res[3] );
      minor = ord( res[4] ) + 256 * ord( res[5] );
      ver = strcat( major, ".", minor );
      set_kb_item( name:"X11/" + port + "/version", value:ver );
      textres = riptext( data:res, begin:40, length:ord( res[24] ) );
      if( textres ) {
        set_kb_item( name:"X11/" + port + "/answer", value:textres );
        extra = "Server answered with: " + textres;
      }
      set_kb_item( name:"X11/" + port + "/open", value:TRUE );
      set_kb_item( name:"X11/open", value:TRUE );

      register_service( port:port, proto:"X11" );
      register_and_report_cpe( app:"X Windows Server", ver:ver, base:"cpe:/a:x.org:x11:", expr:"^([0-9.]+([a-z0-9]+)?)", regPort:port, insloc:port + "/tcp", extra:extra );
    }

    if( result == 2 ) { # Authenticate

      textres = riptext( data:res, begin:8, length:ord( res[1] ) );
      if( textres ) {
        set_kb_item( name:"X11/" + port + "/answer", value:textres );
        extra = "Server answered with: " + textres;
      }

      set_kb_item( name:"X11/" + port + "/open", value:FALSE );
      register_service( port:port, proto:"X11" );
      register_and_report_cpe( app:"X Windows Server", cpename:"cpe:/a:x.org:x11", regPort:port, insloc:port + "/tcp", extra:extra );
    }
  }
}

exit( 0 );
