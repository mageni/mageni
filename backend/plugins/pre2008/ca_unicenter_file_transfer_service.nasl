###############################################################################
# OpenVAS Vulnerability Test
#
# CA Unicenter's File Transfer Service is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10032");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CA Unicenter's File Transfer Service is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Windows");
  script_dependencies("find_service.nasl");
  script_require_ports(3104, 4105);
  script_require_udp_ports(4104);

  script_tag(name:"solution", value:"Block those ports from outside communication.");

  script_tag(name:"summary", value:"CA Unicenter's File Transfer Service uses ports TCP:3104, UDP:4104 and
  TCP:4105 for communication between its clients and other CA Unicenter servers.");

  script_tag(name:"impact", value:"These ports are open, meaning that CA Unicenter File Transfer
  service is probably running, and is open for outside attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if( get_port_state( 3104 ) && get_port_state( 4105 ) && get_udp_port_state( 4104 ) ) {

  soctcp = open_sock_tcp( 3104 );
  if( ! soctcp )
    exit( 0 );
  else
    close( soctcp );

  soctcp = open_sock_tcp( 4105 );
  if( ! soctcp )
    exit( 0 );
  else
    close( soctcp );

  socudp4104 = open_sock_udp( 4104 );

  if( socudp4104 ) {
    send( socket:socudp4104, data:string( "\r\n" ) );
    result = recv( socket:socudp4104, length:1000 );
    close( socudp4104 );
    if( strlen( result ) > 0 ) {
      security_message( port:0 );
      exit( 0 );
    }
  }
}

exit( 0 );