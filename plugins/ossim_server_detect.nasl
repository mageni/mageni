###############################################################################
# OpenVAS Vulnerability Test
# $Id: ossim_server_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# OSSIM Server Detection
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
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
  script_oid("1.3.6.1.4.1.25623.1.0.9000001");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-08-21 14:43:25 +0200 (Thu, 21 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OSSIM Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 40001);

  script_xref(name:"URL", value:"http://www.ossim.net");

  script_tag(name:"solution", value:"If possible, filter incoming connections to the service so that it is
  used by trusted sources only.");
  script_tag(name:"summary", value:"A OSSIM server is listening on the remote system.

  Description :

  The remote system is running an OSSIM server. OSSIM (Open Source
  Security Information Management) is a centralized security management
  information system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:40001 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

rand = rand() % 10;
data = 'connect id="' + rand + '" type="sensor"\n';
send( socket:soc, data:data );
recv = recv( socket:soc, length:64 );
close( soc );

if( recv == 'ok id="' + rand + '"\n' ) {
  log_message( port:port );
  register_service( port:port, ipproto:"tcp", proto:"ossim_server" );
}

exit( 0 );