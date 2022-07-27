###############################################################################
# OpenVAS Vulnerability Test
# $Id: amanda_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Amanda client version
#
# Authors:
# Paul Ewing <ewing@ima.umn.edu>
#
# Copyright:
# Copyright (C) 2000 Paul J. Ewing Jr.
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
  script_oid("1.3.6.1.4.1.25623.1.0.10462");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Amanda client version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Paul J. Ewing Jr.");
  script_family("Service detection");
  script_require_udp_ports(10080, 10081);

  script_tag(name:"summary", value:"This detects the Amanda backup system client
  version. The client version gives potential attackers additional
  information about the system they are attacking.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

function get_version( soc, port, timeout ) {

  local_var result, temp, version, data;

  if ( ! isnull( timeout ) )
    result = recv( socket:soc, length:2048, timeout:timeout );
  else
    result = recv( socket:soc, length:2048 );

  if( result ) {
    if( egrep( pattern:"^[^ ]+ [0-9]+\.[0-9]+", string:result ) ) {
      temp = strstr( result, " " );
      temp = temp - " ";
      temp = strstr( temp, " " );
      version = result - temp;
      data = string( "Amanda version: ", version );
      log_message( port:port, data:data, protocol:"udp" );
      register_service( port:port, ipproto:"udp", proto:"amanda" );
      set_kb_item( name:"Amanda/running", value:TRUE );
    }
  }
}

req = 'Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\nSERVICE ' + rand_str( length:8 ) + '\n';

port1 = 10080;
if( get_udp_port_state( port1 ) ) {
  soc1 = open_sock_udp( port1 );
  if( soc1 ) {
    send( socket:soc1, data:req );
    get_version( soc:soc1, port:port1, timeout:NULL );
    close( soc1 );
  }
}

port2 = 10081;
if( get_udp_port_state( port2 ) ) {
  soc2 = open_sock_udp( port2 );
  if( soc2 ) {
    send( socket:soc2, data:req );
    get_version( soc:soc2, port:port2, timeout:1 );
    close( soc2 );
  }
}

exit( 0 );