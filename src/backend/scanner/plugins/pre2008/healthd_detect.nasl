###############################################################################
# OpenVAS Vulnerability Test
# $Id: healthd_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# HealthD detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10731");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("HealthD detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/healthd", "Services/unknown", 1281);

  script_tag(name:"solution", value:"Configure your firewall to block access to this port.");

  script_tag(name:"summary", value:"The FreeBSD Health Daemon was detected.

  The HealthD provides remote administrators with information about the
  current hardware temperature, fan speed, etc, allowing them to monitor
  the status of the server.");

  script_tag(name:"impact", value:"Such information about the hardware's current state might be sensitive.
  It is recommended that you do not allow access to this service from the network.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/healthd" );
if( ! port ) port = get_unknown_port( default:1281 );

if( get_port_state( port ) ) {

  soc = open_sock_tcp(port);

  if( soc ) {
    data = string( "foobar" );
    send( socket:soc, data:data );
    res = recv( socket:soc, length:8192 );

    if( "ERROR: Unsupported command" >< res ) {

      set_kb_item( name:"healthd/installed", value:TRUE );
      register_service( port:port, proto:"healthd");

      data = string("VER d");
      send( socket:soc, data:data );
      res = recv( socket:soc, length:8192 );
      close( soc );

      if( "ERROR: Unsupported command" >< res ) {
        security_message( port:port );
      } else {
        data = string( "The HealthD version we found is: ", res, "\n" );
        security_message( port:port, data:data );
      }
      exit( 0 );
    }
    close( soc );
    exit( 99 );
  }
}

exit( 0 );