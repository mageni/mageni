###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rmi_registry_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# RMI-Registry Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105839");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-08-01 09:40:35 +0200 (Mon, 01 Aug 2016)");
  script_name("RMI-Registry Detection");

  script_tag(name:"summary", value:"This Script detects the RMI-Registry Service");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1099);
  exit(0);
}

include("host_details.inc");
include("byte_func.inc");
include("misc_func.inc");

port = get_unknown_port( default:1099 );

soc = open_sock_tcp( port );

if( ! soc ) exit( 0 );

req = 'JRMI' + raw_string( 0x00, 0x02, 0x4b );

send(socket:soc, data:req);
res = recv( socket:soc, length:128, min:7 );
close( soc );

if( hexstr( res[0] ) != '4e' || ( getword( blob:res, pos:1 ) + 7 ) != strlen( res ) )
  exit( 0 );

register_service( port:port, proto:"rmi_registry" );
log_message( port:port, data:'The RMI-Registry Service is running at this port');
exit( 0 );