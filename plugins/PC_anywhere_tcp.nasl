###############################################################################
# OpenVAS Vulnerability Test
# $Id: PC_anywhere_tcp.nasl 11031 2018-08-17 09:42:45Z cfischer $
#
# Description: pcAnywhere TCP
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Changes by Tenable Network Security : cleanup + better detection
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.10794");
  script_version("$Revision: 11031 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:42:45 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("pcAnywhere TCP");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  # Only two ports used and not configurable: https://support.symantec.com/en_US/article.TECH106675.html
  script_require_ports(65301, 5631);

  script_tag(name:"summary", value:"pcAnywhere is running on this port.");

  script_tag(name:"solution", value:"Disable this service if you do not use it.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

foreach port( make_list( 65301, 5631 ) ) {

  if( ! service_is_unknown( port:port ) ) continue;
  if( ! get_port_state( port ) ) continue;
  if( ! soc = open_sock_tcp( port ) ) continue;

  send( socket:soc, data:raw_string(0,0,0,0) );
  r = recv( socket:soc, length:36 );
  close( soc );
  if( r && "Please press <" >< r ) {
    register_service( port:port, proto:"pcanywheredata" );
    log_message( port:port );
  }
}

exit( 0 );