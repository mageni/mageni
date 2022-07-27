###############################################################################
# OpenVAS Vulnerability Test
# $Id: gravity_board_x_detect.nasl 9947 2018-05-24 10:31:47Z ckuersteiner $
#
# Gravity Board X Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100100");
  script_version("$Revision: 9947 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-24 12:31:47 +0200 (Thu, 24 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gravity Board X Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.gravityboardx.com/");

  script_tag(name:"summary", value:"This host is running Gravity Board X, a free forum software written
  in PHP and MySQL.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/gravity", "/forum", "/board", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:".*Gravity Board X.*", string:buf, icase:TRUE ) && egrep( pattern:"Powered by", string:buf, icase:TRUE ) ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:"<a href=[^>]+>Gravity Board X</a>.*v([0-9.]+ *[BETA]*)", icase:TRUE );
    if( ! isnull( version[1] ) ) vers = chomp( version[1] );

    set_kb_item(name: "gravity_board_x/installed", value: TRUE);

    cpe = build_cpe(value: vers, exp: "^([0-9.]+\.[0-9])\.?([a-z0-9]+)?",
                    base:"cpe:/a:gravityboardx:gravity_board_x:");
    if (!cpe)
      cpe = "cpe:/a:gravityboardx:gravity_board_x";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Gravity Board X",
                                              version:vers,
                                              install:install,
                                              concluded:version[0],
                                              cpe:cpe ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
