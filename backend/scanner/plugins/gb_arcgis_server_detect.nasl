###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcgis_server_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# ArcGIS Server Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113040");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 13:04:05 +0200 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ArcGIS Server Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of ArcGIS Server.

    This script sends HTTP GET request and try to get the version from the
    response.");

  exit(0);
}

include( "cpe.inc" );
include( "http_func.inc" );
include( "host_details.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );

res = http_get_cache( port: port, item: "/arcgis/rest/services/" );

if( "ArcGIS REST Services Directory" >< res ) {
  version = "unknown";

  vers = eregmatch( pattern: "<b>Current Version: </b>(([0-9]+\.)+[0-9]+)", string: res );
  if( !isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name: "arcgis/version", value: version );
  }

  set_kb_item( name: "arcgis/installed", value: TRUE );

  cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:esri:arcgis:" );
  if (!cpe) cpe = 'cpe:/a:esri:arcgis';

  register_product( cpe: cpe, location: "/arcgis/", port: port );

  log_message( data: build_detection_report( app: "ArcGIS Server", version: version, install: "/arcgis/", cpe: cpe,
                                             concluded: vers[0] ),
               port: port );
  exit( 0 );
}

exit( 0 );

