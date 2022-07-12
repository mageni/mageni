# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111055");
  script_version("2022-03-25T12:37:04+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:01:15 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-11-21 19:00:00 +0100 (Sat, 21 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Icinga Web 2 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Icinga Web 2.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit ( 0 );

detection_patterns = make_list(
  "<title>Icinga Web 2 Login",
  "Icinga Web 2 &copy;",
  "var icinga = new Icinga"
);

foreach dir( make_list_unique( "/", "/icinga", "/icingaweb2", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/authentication/login";
  req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", "_chc=1" ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {

      found++;

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( found > 0 ) {

    version = "unknown";
    concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"icinga/icingaweb2/detected", value:TRUE );
    set_kb_item( name:"icinga/icingaweb2/http/detected", value:TRUE );
    set_kb_item( name:"icinga/icingaweb2/http/port", value:port );
    set_kb_item( name:"icinga/icingaweb2/http/" + port + "/installs",
                 value:port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#" + concludedUrl );
  }
}

exit( 0 );
