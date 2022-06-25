# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800280");
  script_version("2022-01-18T12:40:16+0000");
  script_tag(name:"last_modification", value:"2022-01-19 11:07:58 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SQLiteManager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SQLiteManager.");

  script_xref(name:"URL", value:"https://www.sqlabs.com/sqlitemanager.php");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/sqlitemanager", "/SQLiteManager", "/sqlite", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/main.php", port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  if( ">Official SQliteManager Homepage</a>" >< res || '"sqlmVersion">Welcome to' >< res ) {

    version = "unknown";

    ver = eregmatch( pattern:"> version ([0-9.]+)", string:res );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    set_kb_item( name:"sqlitemanager/detected", value:TRUE );
    set_kb_item( name:"sqlitemanager/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sqlitemanager:sqlitemanager:" );
    if( ! cpe )
      cpe = "cpe:/a:sqlitemanager:sqlitemanager";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"SQLiteManager", version:version, install:install,
                                              cpe:cpe, concluded:ver[0] ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
