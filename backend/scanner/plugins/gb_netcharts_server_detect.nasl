###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netcharts_server_detect.nasl 10935 2018-08-13 07:46:25Z cfischer $
#
# NetCharts Server Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805642");
  script_version("$Revision: 10935 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-13 09:46:25 +0200 (Mon, 13 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-06-03 12:12:21 +0530 (Wed, 03 Jun 2015)");
  script_name("NetCharts Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Visual Mining NetCharts Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:8001 );

# nb: The Server is Listening on root directory
res = http_get_cache( item:"/Documentation/misc/about.jsp", port:port );

if( res && "NetCharts Server" >< res && "Visual Mining" >< res ) {

  install = "/";
  version = "unknown";

  vers = eregmatch( pattern:"Version.*([0-9.]+).*&copy", string:res );
  if( ! isnull( vers[1] ) ) version = vers[1];

  set_kb_item( name:"netchart/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:visual_mining:netcharts_server:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:visual_mining:netcharts_server";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Visual Mining/NetChart",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );