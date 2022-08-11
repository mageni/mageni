###############################################################################
# OpenVAS Vulnerability Test
# $Id: amanda_version.nasl 11036 2018-08-17 10:55:57Z cfischer $
#
# Amanda Index Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.10742");
  script_version("$Revision: 11036 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 12:55:57 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Amanda Index Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Service detection");
  script_require_ports(10082);
  script_dependencies("find_service.nasl");

  script_tag(name:"summary", value:"This test detects the Amanda Index Server's
  version by connecting to the server and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Amanda Index Server version";

port = 10082;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
res = recv_line( socket:soc, length:1000 );
close( soc );
if( "AMANDA index server" >!< res ) exit( 0 );

version = "unknown";
install = port + "/tcp";

register_service( port:port, proto:"amandaidx" );
set_kb_item( name:"amanda/index_server/detected", value:TRUE );

if( concl = ereg( pattern:"^220 .* AMANDA index server \(.*\).*", string:res ) ) {
  version = ereg_replace( pattern:"^220 .* AMANDA index server \((.*)\).*", string:res, replace:"\1" );
  set_kb_item( name:"amanda/index_server/version", value:version );
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:amanda:amanda:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:amanda:amanda:";

register_product( cpe:cpe, location:install, port:port );
log_message( data:build_detection_report( app:"Amanda Index Server",
                                          version:version,
                                          install:port,
                                          cpe:cpe,
                                          concluded:concl ),
                                          port:port );

exit( 0 );