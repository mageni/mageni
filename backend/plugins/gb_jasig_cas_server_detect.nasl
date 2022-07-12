###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jasig_cas_server_detect.nasl 14334 2019-03-19 14:35:43Z cfischer $
#
# Jasig Central Authentication Service Server Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806501");
  script_version("$Revision: 14334 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:35:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-10-19 13:01:26 +0530 (Mon, 19 Oct 2015)");
  script_name("Jasig Central Authentication Service Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Jasig Central Authentication Service Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/cas", "/cas-server-webapp", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/login", port:port );

  if( rcvRes =~ "Powered by.*>Jasig Central Authentication Service" &&
      'login' >< rcvRes && 'id="cas' >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:">Jasig Central Authentication Service ([0-9.]+)", string:rcvRes );
    if( ver[1] ) version = ver[1];

    set_kb_item( name:"www/" + port + "/cas", value:version );
    set_kb_item( name:"Jasig CAS server/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apereo:central_authentication_service:" );
    if( ! cpe )
      cpe = "cpe:/a:apereo:central_authentication_service";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Jasig Central Authentication Service Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );