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
  script_oid("1.3.6.1.4.1.25623.1.0.112672");
  script_version("2019-12-06T14:44:11+0000");
  script_tag(name:"last_modification", value:"2019-12-06 14:44:11 +0000 (Fri, 06 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-05 10:28:11 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("forma.lms Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether Forma Learning Management System
  is present on the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"http://www.formalms.org/");

  exit(0);
}

CPE = "cpe:/a:formalms:formalms:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 443 );

foreach dir( make_list_unique( "/", "/formalms", cgi_dirs( port: port ) ) ) {

  location = dir;
  if( location == "/" )
    location = "";

  url = location + "/";

  buf = http_get_cache( port: port, item: url );

  if( buf =~ "^HTTP/[0-9]\.[0-9] 200" &&
      ( "Copyright (c) forma.lms" >< buf || "Powered by forma.lms CE" >< buf ||
        '<meta name="Generator" content="www.formalms.org' >< buf || '<link rel="Copyright" href="http://www.formalms.org/copyright"' >< buf ) ) {

    set_kb_item( name: "formalms/detected", value: TRUE );

    version = "unknown";

    # <meta name="Generator" content="www.formalms.org 1.4.2" />
    ver = eregmatch( string: buf, pattern: '<meta name="Generator" content="www\\.formalms\\.org ([0-9.]+)" />' );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      concl_url = report_vuln_url( port: port, url: url, url_only: TRUE );
    } else {
      vers_url = location + "/changelog.txt";

      vers_buf = http_get_cache( port: port, item: vers_url );
      ver = eregmatch( string: vers_buf, pattern: "(FORMA|forma\.lms) ([0-9.]+)" );
      if( vers_buf =~ "^HTTP/1\.[01] 200" && ! isnull( ver[2] ) ) {
        version = ver[2];
        concl_url = report_vuln_url( port: port, url: vers_url, url_only: TRUE );
      }
    }

    register_and_report_cpe( app: "Forma Learning Management System",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: dir,
                             regPort: port,
                             regService: "www",
                             conclUrl: concl_url );

    exit( 0 );
  }
}

exit( 0 );
