###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_detect.nasl 12000 2018-10-21 10:49:25Z cfischer $
#
# MapServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800547");
  script_version("$Revision: 12000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 12:49:25 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_name("MapServer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of the MapServer and its installed version.

  This script sends a HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

if( host_runs( "Windows" ) == "yes" )
  files = make_list( "/cgi-bin/mapserv.exe" );
else if( host_runs( "Linux" ) == "yes" )
  files = make_list( "/cgi-bin/mapserv" );
else
  files = make_list( "/cgi-bin/mapserv", "/cgi-bin/mapserv.exe" );

port = get_http_port(default:80);

foreach file( files ) {

  url = file + "?map=";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "MapServer" >!< res )
    continue;

  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  version = "unknown";
  install = "/";

  mapVer = eregmatch( pattern:"MapServer version ([0-9]\.[0-9.]+)", string:res );
  if( mapVer[1] ) {
    version = mapVer[1];
    set_kb_item( name:"MapServer/ver", value:version );
  }

  set_kb_item( name:"MapServer/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:umn:mapserver:" );
  if( ! cpe )
    cpe = "cpe:/a:umn:mapserver";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"MapServer",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:version ),
                                            port:port );
  exit( 0 );
}

exit( 0 );
