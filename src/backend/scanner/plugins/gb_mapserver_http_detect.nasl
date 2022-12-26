# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800547");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MapServer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection for MapServer.");

  script_xref(name:"URL", value:"https://mapserver.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

if( os_host_runs( "Windows" ) == "yes" )
  files = make_list( "/cgi-bin/mapserv.exe" );
else if( os_host_runs( "Linux" ) == "yes" )
  files = make_list( "/cgi-bin/mapserv" );
else
  files = make_list( "/cgi-bin/mapserv", "/cgi-bin/mapserv.exe" );

port = http_get_port( default:80 );

foreach file( files ) {

  url = file + "?map=";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "MapServer" >!< res )
    continue;

  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  version = "unknown";
  install = "/";

  # <!-- MapServer version 6.0.1
  vers = eregmatch( pattern:"MapServer version ([0-9]\.[0-9.]+)", string:res );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name:"mapserver/detected", value:TRUE );
  set_kb_item( name:"mapserver/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:umn:mapserver:" );
  if( ! cpe )
    cpe = "cpe:/a:umn:mapserver";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"MapServer", version:version, install:install, cpe:cpe,
                                            concludedUrl:conclUrl, concluded:vers[0] ),
               port:port );
  exit( 0 );
}

exit( 0 );
