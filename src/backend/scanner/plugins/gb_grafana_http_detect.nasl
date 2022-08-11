###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grafana_http_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Grafana Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113259");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-31 12:03:00 +0200 (Fri, 31 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grafana Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks if Grafana is running on the target system
  and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://grafana.com/");

  exit(0);
}

CPE = "cpe:/a:grafana:grafana:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 3000 );

foreach location( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  url = location;
  if( url == "/" )
    url = "";

  url = url + "/grafana/login";

  buf = http_get_cache( item: url, port: port );
  if( buf =~ 'base href="[^"]*/grafana/"' ) {
    set_kb_item( name: "grafana/detected", value: TRUE );
    set_kb_item( name: "grafana/http/port", value: TRUE );

    version = "unknown";

    vers = eregmatch( string: buf, pattern: '(latest[Vv]ersion|commit)[^,}]+,[\'"]version[\'"]:[\'"]([0-9.]+)[\'"]' );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
      set_kb_item( name: "grafana/version", value: version );
    }

    register_and_report_cpe( app: "Grafana",
                             ver: version,
                             concluded: vers[0],
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: location,
                             regPort: port,
                             conclUrl: url );

    exit( 0 );
  }
}

exit( 0 );
