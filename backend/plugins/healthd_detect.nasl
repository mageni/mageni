###############################################################################
# OpenVAS Vulnerability Test
#
# HealthD detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> / SecuriTeam
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
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-25 10:44:06 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("HealthD detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2005 SecuriTeam");
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
include("port_service_func.inc");
include("http_func.inc"); # For make_list_unique

unkn_ports = unknown_get_ports( default_port_list:make_list( 1281 ) );
if( unkn_ports && is_array( unkn_ports ) )
  ports = make_list( ports, unkn_ports );

health_ports = get_ports_for_service( default_port_list:make_list( 1281 ), proto:"healthd" );
if( health_ports && is_array( health_ports ) )
  ports = make_list( ports, health_ports );

ports = make_list_unique( ports );

foreach port( ports ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  data = string( "foobar" );
  send( socket:soc, data:data );
  res = recv( socket:soc, length:8192 );

  if( "ERROR: Unsupported command" >< res ) {

    set_kb_item( name:"healthd/installed", value:TRUE );
    register_service( port:port, proto:"healthd" );

    data = string("VER d");
    send( socket:soc, data:data );
    res = recv( socket:soc, length:8192 );

    if( "ERROR: Unsupported command" >< res ) {
      security_message( port:port );
    } else {
      data = string( "The HealthD version we found is: ", res, "\n" );
      security_message( port:port, data:data );
    }
  }
  close( soc );
}

exit( 0 );
