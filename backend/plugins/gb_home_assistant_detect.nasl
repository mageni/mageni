###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_home_assistant_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Home Assistant Dashboard Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113249");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-22 11:46:47 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Home Assistant Dashboard Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of the Home Assistant Smart Home Dashboard.");

  script_xref(name:"URL", value:"https://www.home-assistant.io/");

  exit(0);
}

CPE = "cpe:/a:home_assistant:home_assistant:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach location ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  if( location == "/" )
    url = "";
  else
    url = location;

  path = url + "/manifest.json";

  buf = http_get_cache( port: port, item: path );
  if( buf =~ '200 OK' && buf =~ '"name": *"Home Assistant"' ) {
    set_kb_item( name: "home_assistant/detected", value: TRUE );
    set_kb_item( name: "home_assisant/port", value: port );

    register_and_report_cpe( app: "Home Assistant",
                             ver: "unknown",
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: location,
                             regPort: port,
                             conclUrl: path );

    exit( 0 );
  }
}

exit( 0 );
