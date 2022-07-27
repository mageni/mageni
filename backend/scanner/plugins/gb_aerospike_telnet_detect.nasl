###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aerospike_telnet_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Aerospike Database Detection (Telnet)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140131");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-27 13:21:27 +0100 (Fri, 27 Jan 2017)");
  script_name("Aerospike Database Detection (Telnet)");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");
  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3003);
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:3003 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

send( socket:soc, data:'version\n' );
recv = recv( socket:soc, length:512 );

close( soc );

if( "Aerospike" >!< recv ) exit( 0 );

set_kb_item( name:"aerospike/detected", value:TRUE );
cpe = 'cpe:/a:aerospike:database_server';

version = "unknown";

# Aerospike Community Edition build 3.11.0.2
v = eregmatch( pattern:'build ([0-9.-]+)', string:recv );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  replace_kb_item( name:"aerospike/version", value:version );
}

if( "Community Edition" >< recv )
  set_kb_item( name:"aerospike/community_edition", value:TRUE );
else if ( "Enterprise Edition" >< recv )
  set_kb_item( name:"aerospike/enterprise_edition", value:TRUE );

register_product( cpe:cpe, location:port + '/TCP', port:port, service:'aerospike_telnet' );

register_service( port:port, proto:'aerospike_telnet' );

report = build_detection_report( app:"Aerospike Database", version:version, install:port + '/TCP', cpe:cpe, concluded:v[0]);

log_message( port:port, data:report );

exit( 0 );

