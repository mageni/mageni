# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113333");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-13 10:36:44 +0100 (Wed, 13 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MyWebSQL Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether MyWebSQL is present on the
  target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"http://mywebsql.net/");

  exit(0);
}

CPE = "cpe:/a:mywebsql:mywebsql:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach location( make_list_unique( "/", "/mywebsql", cgi_dirs( port: port ) ) ) {
  buf = http_get_cache( port: port, item: location );

  if( buf !~ '<title>MyWebSQL</title>' ) continue;

  set_kb_item( name: "mywebsql/detected", value: TRUE );

  version = "unknown";
  ver = eregmatch( string: buf, pattern: '<span class="version">version ([0-9.]+)</span>', icase: TRUE );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
  }

  register_and_report_cpe( app: "MyWebSQL",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: location,
                           regPort: port,
                           conclUrl: location );

  #nb: exit if installed in root, else continue to check other locations
  if( location == "/" ) exit( 0 );
}

exit( 0 );
