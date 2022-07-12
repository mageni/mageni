###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sangoma_nsc_detect.nasl 8465 2018-01-19 04:50:20Z ckuersteiner $
#
# Sangoma NetBorder/Vega Session Controller Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112183");
  script_version("$Revision: 8465 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 05:50:20 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-11 12:07:00 +0100 (Thu, 11 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sangoma NetBorder/Vega Session Controller Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");

  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script sends an HTTP GET request to figure out whether a web-based service of Sangoma Session Border Controller (SBC)
is running on the target host, and, if so, which version is installed.");

  script_xref(name:"URL", value:"https://www.sangoma.com/products/sbc/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir ( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if ( dir == "/" ) dir = "";

  foreach file ( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    resp = http_get_cache( item:url, port:port );

    if ( "Session Controller" >< resp && 'SNG_logo.png" alt="Sangoma"' >< resp ) {
      installed = TRUE;
      break;
    }
  }

  if ( installed ) {
      set_kb_item( name: "sangoma/nsc/detected", value: TRUE );
      version = "unknown"; #tbd

      register_and_report_cpe( app: "Sangoma NetBorder/Vega Session Controller",
                               cpename: "cpe:/o:sangoma:netborder",
                               base: "cpe:/o:sangoma:netborder:",
                               ver: version,
                               insloc: install,
                               regPort: port);
  }
}

exit(0);
