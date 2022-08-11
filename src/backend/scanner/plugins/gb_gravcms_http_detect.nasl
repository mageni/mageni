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
  script_oid("1.3.6.1.4.1.25623.1.0.112826");
  script_version("2020-09-24T12:59:47+0000");
  script_tag(name:"last_modification", value:"2020-09-25 10:17:15 +0000 (Fri, 25 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-24 12:00:00 +0000 (Thu, 24 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grav CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Grav CMS.");

  script_xref(name:"URL", value:"https://getgrav.org/");

  exit(0);
}

CPE = "cpe:/a:getgrav:gravcms:";

include( "host_details.inc" );
include( "cpe.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "port_service_func.inc" );

port = http_get_port( default: 443 );

buf = http_get_cache( item: "/admin", port: port );

if( buf =~ "HTTP/1\.[01] 200" && "<title>Grav Admin Login" >< buf && "this.GravAdmin = this.GravAdmin" >< buf ) {

  set_kb_item( name: "getgrav/gravcms/detected", value: TRUE );

  version = "unknown";

  # {"message":"Grav v1.6.10",}
  if( vers = eregmatch( pattern:'"message":"Grav v([0-9a-z.-]+)",', string: buf ) ) {
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concluded = http_report_vuln_url( port: port, url: "/admin", url_only: TRUE );
    }
  } else {
    buf = http_get_cache( port: port, item: "/CHANGELOG.md" );
    # # v1.6.26
    # # v1.2.0-rc.3
    if( vers = eregmatch( pattern: "# v([0-9a-z.\-]+)", string: buf ) ) {
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        concluded = http_report_vuln_url( port: port, url: "/CHANGELOG.md", url_only: TRUE );
      }
    }
  }

  register_and_report_cpe( app: "Grav CMS",
                           ver: version,
                           concluded: vers[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: "/",
                           conclUrl: concluded,
                           regPort: port,
                           regService: "www" );

  exit( 0 );
}

exit( 0 );

