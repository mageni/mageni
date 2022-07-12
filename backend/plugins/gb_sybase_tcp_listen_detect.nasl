###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sybase_tcp_listen_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sybase TCP/IP listener
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140129");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-27 09:57:51 +0100 (Fri, 27 Jan 2017)");
  script_name("Sybase TCP/IP listener Detection");

  script_tag(name:"summary", value:"This script detects a Sybase TCP/IP listener server by sending a login packet and checking the response.");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "mssql_version.nasl", "oracle_tnslsnr_version.nasl");
  script_require_ports("Services/unknown", 5000);
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("sybase_func.inc");

port = get_unknown_port( default:5000 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

sql_packet = make_sql_login_pkt( username:"OpenVAS", password:"OpenVAS" );

send( socket:soc, data:sql_packet );
send( socket:soc, data:pkt_lang );

buf = recv( socket:soc, length:255 );

close( soc );

if( "Login failed" >< buf )
{
  set_kb_item( name:"sybase/tcp_listener/detected", value:TRUE );
  register_product( cpe:'cpe:/a:sybase:adaptive_server_enterprise', location:port +'/tcp', port:port, service:"sybase_tcp_listener" );
  register_service( proto:"sybase", port:port, message:'Sybase TCP/IP listener is running at this port.\nCPE: cpe:/a:sybase:adaptive_server_enterprise\n' );

  log_message( port:port, data:'Sybase TCP/IP listener is running at this port.\nCPE: cpe:/a:sybase:adaptive_server_enterprise\n' );
  exit( 0 );
}

exit( 0 );

