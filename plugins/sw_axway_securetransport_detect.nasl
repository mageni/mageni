###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_axway_securetransport_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# Axway SecureTransport Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111019");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-04-22 08:00:00 +0200 (Wed, 22 Apr 2015)");
  script_name("Axway SecureTransport Detection");

  script_tag(name:"summary", value:"Detection of the installation and version
  of a Axway SecureTransport.

  The script sends HTTP GET requests and try to comfirm the Axway SecureTransport
  installation and version from the responses.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
res = http_get_cache( item:"/", port:port );

axwayVer = 'unknown';

if( concluded = eregmatch( string: banner, pattern: "Server: SecureTransport[/]?([0-9.]?)", icase:TRUE ) ) {
  if( concluded[1] && version_is_greater_equal( version:concluded[1], test_version:"5.0" ) ) {
    installed = 1;
    axwayVer = concluded[1];
  }
}

if( res && ( "<title>Axway SecureTransport Login" >< res || "<title>Axway SecureTransport | Login" >< res) ) {

  ver = eregmatch( pattern:'"SecureTransport", "([0-9.]+)"', string:res );

  if( ver[1] ) {
    axwayVer = ver[1];
    concluded = ver;
  }

  installed = 1;
}

if( installed ) {

  set_kb_item( name:"www/" + port + "/axway_securetransport", value:axwayVer );
  set_kb_item( name:"axway_securetransport/installed", value:TRUE );

  cpe = build_cpe( value:axwayVer, exp:"([0-9a-z.]+)", base:"cpe:/a:axway:securetransport:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:axway:securetransport';

  register_product( cpe:cpe, location:"/", port:port );

  log_message( data: build_detection_report( app:"Axway SecureTransport",
                                             version:axwayVer,
                                             install:"/",
                                             cpe:cpe,
                                             concluded:concluded[0] ),
                                             port:port );
}

exit( 0 );
