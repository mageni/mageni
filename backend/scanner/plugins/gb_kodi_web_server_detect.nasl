###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_web_server_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Kodi Web Server Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808282");
  script_version("$Revision: 11021 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)");
  script_name("Kodi Web Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Kodi Web Server.

  This script sends HTTP GET request and try to ensure the presence of
  Kodi Web Server from the response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:8080 );
res  = http_get_cache( port:port, item:"/" );

if( ( "<title>Kodi</title>" >< res && ">Profiles<" >< res &&
      ">Remote<" >< res && ">Music<" >< res ) ||
    ( "Kodi web interface</title>" >< res && 'js/kodi-webinterface.js"></script>' >< res ) ) {

  version = "unknown";
  install = "/";

  data = '[{"jsonrpc":"2.0","method":"Application.GetProperties","params":[["volume","muted","version"]],"id":71}]';
  url  = "/jsonrpc?Application.GetProperties";

  req = http_post_req( port:port, url:url, data:data,
                       accept_header:"text/plain, */*; q=0.01",
                       add_headers:make_array( "Content-Type", "application/json" ) );
  res = http_keepalive_send_recv( port:port, data:req );

  # version":{"major":17,"minor":6
  vers = eregmatch( pattern: 'version".."major":([0-9]+),"minor":([0-9]+)', string:res );
  if( ! isnull( vers[1] ) && ! isnull( vers[2] ) ) {
    version = vers[1] + '.' + vers[2];
    set_kb_item( name:"Kodi/WebServer/version", value:version );
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  set_kb_item( name:"Kodi/WebServer/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kodi:kodi:");
  if( ! cpe )
    cpe = "cpe:/a:kodi:kodi";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Kodi Web Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0],
                                            concludedUrl:conclUrl ),
                                            port:port );
}

exit( 0 );