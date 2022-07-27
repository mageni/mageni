###############################################################################
# OpenVAS Vulnerability Test
# $Id: echo.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# echo Service Detection (TCP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108479");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("echo Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/echo", 7);

  script_tag(name:"summary", value:"Checks if the remote host is running an echo service via TCP.

  Note: The reporting takes place in a separate VT 'echo Service Reporting (TCP + UDP)' (OID: 1.3.6.1.4.1.25623.1.0.100075).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/echo" );
if( ! port ) port = 7;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

vtstrings = get_vt_strings();

echo_string = vtstrings["default"] + "-Echo-Test";

send( socket:soc, data:echo_string );
buf = recv( socket:soc, length:512 );
close( soc );

if( buf == echo_string ) {
  register_service( port:port, proto:"echo" );
  set_kb_item( name:"echo_tcp_udp/detected", value:TRUE );
  set_kb_item( name:"echo_tcp/detected", value:TRUE );
  set_kb_item( name:"echo_tcp/" + port + "/detected", value:TRUE );
  log_message( port:port, data:"An echo service is running at this port." );
}

exit( 0 );