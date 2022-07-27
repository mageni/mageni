###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ikiwiki_webui_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# IkiWiki Detection (Web UI)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113157");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-17 14:52:55 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IkiWiki Detection (Web UI)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of IkiWiki via Web UI.

  The script sends a GET request to the server and attempts to
  detect the presence of IkiWiki.");

  script_xref(name:"URL", value:"https://ikiwiki.info/");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );

foreach location ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {

  if( location == "/" )
    dir = "";
  else
    dir = location;

  dir = dir + "/ikiwiki/";
  res = http_get_cache( port: port, item: dir );

  if( res =~ '<p>This wiki is powered by <a href="http://ikiwiki.info/">ikiwiki</a>\\.') {
    set_kb_item( name: "ikiwiki/detected", value: TRUE );
    set_kb_item( name: "ikiwiki/www/detected", value: TRUE );

    version = "unknown";
    vers = eregmatch( string: res, pattern: '\\(Currently running version ([0-9.]+)\\.\\)</p>' );

    if( vers[1] ) {
      version = vers[1];
      set_kb_item( name: "ikiwiki/webui/" + port + "/concluded", value: vers[0] );
    }

    set_kb_item( name: "ikiwiki/webui/port", value: port );
    set_kb_item( name: "ikiwiki/webui/" + port + "/version", value: version );
    set_kb_item( name: "ikiwiki/webui/" + port + "/location", value: location );
    break;
  }
}

exit( 0 );
