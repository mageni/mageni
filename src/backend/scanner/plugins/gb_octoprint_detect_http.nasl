###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_octoprint_detect_http.nasl 13796 2019-02-20 15:50:37Z cfischer $
#
# OctoPrint Version Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107342");
  script_version("$Revision: 13796 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 16:50:37 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OctoPrint Version Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of OctoPrint Web UI for 3D printers using HTTP.");

  script_xref(name:"URL", value:"https://octoprint.org/download/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( banner = egrep( string:banner, pattern:"Basic realm.+OctoPrint", icase:TRUE ) ) {
  found = TRUE;
  auth  = TRUE;
  concluded = chomp( banner );
}

if( ! found ) {
  buf = http_get_cache( item:"/", port:port );
  # nb: Seems newer versions have a new login page, those are also not exposing the version without a login.
  if( buf && buf =~ "^HTTP/1\.[01] 200" && ( "OctoPrint</title>" >< buf && "octoprint.org" >< buf ) || "<title>OctoPrint Login</title>" >< buf ) {
    found = TRUE;
    auth  = FALSE;
  }
}

if( found ) {

  install = "/";
  version = "unknown";
  conclUrl = report_vuln_url( port:port, url:"/", url_only:TRUE );

  set_kb_item( name:"octoprint/detected", value:TRUE );
  set_kb_item( name:"octoprint/http/port", value:port );

  if( auth )
    set_kb_item( name:"octoprint/detected/auth", value:TRUE );
  else
    set_kb_item( name:"octoprint/detected/noauth", value:TRUE );

  vers = eregmatch( pattern:'var DISPLAY_VERSION = "([0-9.]+)"', string:buf, icase:TRUE );
  if( vers[1] ) {
    version = vers[1];
    concluded = vers[0];
  }

  set_kb_item( name:"octoprint/http/version", value:version );
  set_kb_item( name:"octoprint/http/concluded", value:concluded );
  register_and_report_cpe( app:"OctoPrint Web UI", ver:version, concluded:concluded, base:"cpe:/a:octoprint:octoprint:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www", conclUrl:conclUrl );
}

exit( 0 );