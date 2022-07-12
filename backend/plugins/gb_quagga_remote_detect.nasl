###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quagga_remote_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Quagga Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105551");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-16 16:56:28 +0100 (Tue, 16 Feb 2016)");
  script_name("Quagga Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/quagga", 2602);
  exit(0);
}

include("host_details.inc");

port = get_kb_item( "Services/quagga" );
if( ! port ) port = 2602;

if( ! get_port_state( port ) ) exit( 0 );

banner = get_kb_item( "FindService/tcp/" + port + "/help" );

if( "hello, this is quagga" >!< tolower( banner ) ) exit( 0 );

set_kb_item( name:"quagga/installed", value:TRUE);

cpe = 'cpe:/a:quagga:quagga';
vers = 'unknown';

version = eregmatch( pattern:'Hello, this is [qQ]uagga \\(version ([^)]+)\\)', string:banner );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:port + "/tcp", port:port );

log_message( port:port, data: build_detection_report( app:"Quagga",
                                                      version:vers,
                                                      install:port + "/tcp",
                                                      cpe:cpe,
                                                      concluded:'telnet banner')
           );

exit( 0 );

