# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.113749");
  script_version("2020-09-02T12:33:24+0000");
  script_tag(name:"last_modification", value:"2020-09-03 09:52:01 +0000 (Thu, 03 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 14:30:32 +0200 (Wed, 02 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Webtrekk Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Webtrekk.");

  script_xref(name:"URL", value:"https://www.webtrekk.com/");

  exit(0);
}

CPE = "cpe:/a:mapp:webtrekk:";

include( "host_details.inc" );
include( "cpe.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "list_array_func.inc" );
include( "port_service_func.inc" );

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  buf = http_get_cache( item: dir, port: port );

  if( buf !~ 'src="[^"]*/webtrekk[^"]*[.]js' )
    continue;

  set_kb_item( name: "webtrekk/detected", value: TRUE );

  version = "unknown";

  vers_url = eregmatch( string: buf, pattern: 'src="([^"]*webtrekk_v[^"]*[.]js)' );

  if( ! isnull( vers_url[1] ) ) {
    vers_url = ereg_replace( string: vers_url[1], pattern: "https?://[^/]*", replace: "" );
    vers_buf = http_get_cache( item: vers_url, port: port );
    vers = eregmatch( string: vers_buf, pattern: 'this.version ?= ?"?([0-9]+)"?' );
    if( ! isnull( vers[1] ) ) {
      undotted_vers = vers[1];
      version = undotted_vers[0] + "." + undotted_vers[1] + "." + undotted_vers[2] + undotted_vers[3];
    }
  }

  register_and_report_cpe( app: "Webtrekk",
                           ver: version,
                           concluded: vers[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: dir,
                           regPort: port,
                           regService: "www",
                           conclUrl: vers_url );

  break;
}

exit( 0 );
