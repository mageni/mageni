###############################################################################
# OpenVAS Vulnerability Test
# $Id: tftgallery_detect.nasl 12315 2018-11-12 09:24:01Z cfischer $
#
# TFT Gallery Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100324");
  script_version("$Revision: 12315 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 10:24:01 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TFT Gallery Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.tftgallery.org");

  script_tag(name:"summary", value:"This host is running TFT Gallery, an easy-to-use image gallery
  using PHP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/gallery", "/photos", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf )
    continue;

  if( egrep( pattern:'<meta name="generator" content="(TFT Gallery|TFTgallery)', string:buf, icase:TRUE ) ) {

    version = "unknown";
    vers = eregmatch( string:buf, pattern: "(TFT Gallery|TFTgallery) ([0-9.]+)", icase:TRUE );

    if( ! isnull( vers[2] ) )
      version = chomp( vers[2] );

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/tftgallery", value:tmp_version );
    set_kb_item( name:"tftgallery/detected", value:TRUE );

    register_and_report_cpe( app:"TFT Gallery",
                             ver:version,
                             concluded:vers[0],
                             base:"cpe:/a:tftgallery:tftgallery:",
                             expr:"^([0-9.]+)",
                             insloc:install,
                             regPort:port );
    exit( 0 );
  }
}

exit( 0 );