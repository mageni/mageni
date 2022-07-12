###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cambium_networks_services_server_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cambium Networks Services Server Detection
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113059");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-30 10:23:24 +0100 (Thu, 30 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks Services Server Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This scripts sends an HTTP GET request to figure out whether Cambium Networks Services Server is installed on the target host, and, if so, which version.");

  script_xref(name:"URL", value:"https://www.cambiumnetworks.com/products/management/cns-server/");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );
foreach dir ( make_list_unique( "/", cgi_dirs( port: port ) ) ) {
  foreach file ( make_list( "/", "/index.html" ) ) {

    if( dir == "/" ) url = file;
    else url = dir + file;

    resp = http_get_cache( item: url, port: port );

    if( resp =~ "<title>Cambium Networks Services Server</title>" && resp =~ 'href="http://cambiumnetworks.com"' ) {

      version_match = eregmatch( pattern: "<i>\(([0-9.]+)\)</i>", string: resp );
      version = "unknown";
      if ( version_match[1] ) version = version_match[1];

      set_kb_item( name: "cambium-networks/services-server/detected", value: TRUE );
      register_and_report_cpe( app: "Cambium Networks Services Server", ver: version, concluded: version_match[0], base: "cpe:/a:cambium-networks:services-server:", expr: "^([0-9.]+)", insloc: dir, regPort: port );
      exit( 0 );
    }
  }
}

