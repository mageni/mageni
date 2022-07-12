###############################################################################
# OpenVAS Vulnerability Test
# $Id: fsp_detection.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Detect FSP Compatible Hosts
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11987");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect FSP Compatible Hosts");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_udp_ports(21, 2000, 2221);

  script_xref(name:"URL", value:"http://fsp.sourceforge.net/");

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming traffic to this
port.");

  script_tag(name:"summary", value:"A file transfer program is listening on the remote port.

Description :

The remote host is running a FSP (File Service Protocol) compatible product. FSP is a protocol designed to serve
file on top of the UDP protocol.

Make sure that the use of this program is done in accordance with your corporate security policy.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

i = 0;

foreach port( make_list( 21, 2000, 2221 ) ) {

  i++;

  if( ! get_udp_port_state( port ) ) continue;

  # This is UDP based protocol ...
  udpsock = open_sock_udp( port );
  if( ! udpsock ) continue;
  data = raw_string( 0x10, 0x44, 0xF0, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  send( socket:udpsock, data:data );

  if( i == 1 ) {
    z = recv( socket:udpsock, length:1024 );
  } else {
    z = recv( socket:udpsock, length:1024, timeout:0 );
  }

  close( udpsock );

  if( z ) {
    if( z[0] == raw_string( 0x10 ) ) {
      mlen = ord( z[7] );
      Server = "";
      for( i = 0; i < mlen - 1; i++ ) {
        Server = string( Server, z[12+i] );
      }

      Server -= string( "\n" );
      if( ! get_kb_item( string( "fsp/banner/", port ) ) )
        set_kb_item( name:string( "fsp/banner/", port ), value:Server );
      set_kb_item( name:"fsp_compatible_host/identified", value:TRUE );

      report = "The remote sotware is : " + Server;
      log_message( port:port, data:report, protocol:"udp" );
      register_service( port:port, ipproto:"udp", proto:"fsp" );
      exit( 0 );
    }
  }
}

exit( 0 );