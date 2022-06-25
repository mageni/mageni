###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_obby_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# obby Service Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111045");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-05 09:00:00 +0100 (Thu, 05 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("obby Service Detection");

  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/obby", 6522);

  script_tag(name:"summary", value:"The script checks the presence of a obby service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item( "Services/obby" );
if ( ! port ) port = 6522;

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket: soc, data: "TEST\r\n\r\n" );

    buf = recv( socket:soc, length:64 );
    close( soc );

    if( banner = egrep( string: buf, pattern: "obby_welcome" ) ) {

      version = "unknown";
      register_service(port:port, proto:"obby");
      set_kb_item( name:"obby/" + port + "/version", value: version );
      set_kb_item( name:"obby/" + port + "/installed", value: TRUE );

      cpe = 'cpe:/a:ubuntu_developers:obby';

      register_product( cpe:cpe, location:port + '/tcp', port:port );

      log_message( data: build_detection_report( app:"obby",
                                                     version:version,
                                                     install:port + '/tcp',
                                                     cpe:cpe,
                                                     concluded:banner),
                                                     port:port);
    }
  }
}

exit(0);
