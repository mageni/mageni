###################################################################
# OpenVAS Vulnerability Test
# $Id: cifs445.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# SMB/CIFS Server Detection
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11011");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB/CIFS Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script detects whether port 445 and 139 are open and
  if they are running a CIFS/SMB server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("misc_func.inc");

flag = 0;
vt_strings = get_vt_strings();

# TODO: Check all unknown ports. At least Samba can listen on other ports...

if( get_port_state( 445 ) ) {

  soc = open_sock_tcp( 445 );
  if( soc ) {
    r = smb_neg_prot( soc:soc );
    close( soc );
    if( r ) {
      register_service( port:445, proto:"cifs" );
      log_message( port:445, data:"A CIFS server is running on this port" );
      set_kb_item( name:"SMB/transport", value:445 );
      flag = 1;
    }
  }
}

if( get_port_state( 139 ) ) {

  soc = open_sock_tcp( 139 );
  if( soc ) {
    nb_remote = netbios_name( orig:string( vt_strings["default_rand"] ) );
    nb_local  = netbios_redirector_name();
    session_request = raw_string( 0x81, 0x00, 0x00, 0x44 ) +
                      raw_string( 0x20 ) +
                      nb_remote +
                      raw_string( 0x00, 0x20 ) +
                      nb_local  +
                      raw_string( 0x00 );

    send( socket:soc, data:session_request );
    r = recv( socket:soc, length:4 );
    close( soc );
    if( r && ( ord(r[0] ) == 0x82 || ord( r[0] ) == 0x83 ) ) {
      register_service( port:139, proto:"smb" );
      log_message( port:139, data:"A SMB server is running on this port" );
      if( ! flag ) set_kb_item( name:"SMB/transport", value:139 );
    }
  }
}

exit( 0 );