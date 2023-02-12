# Copyright (C) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111079");
  script_version("2023-02-01T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"creation_date", value:"2016-01-27 11:00:00 +0100 (Wed, 27 Jan 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lighttpd Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/banner");

  script_xref(name:"URL", value:"http://www.lighttpd.net");

  script_tag(name:"summary", value:"HTTP based detection of the Lighttpd HTTP server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

url = "/";

# Server: lighttpd/1.4.55
# Server: lighttpd
# Server: lighttpd/1.4.26-devel-v14.12.2-r1
if( concl = egrep( string:banner, pattern:"^[Ss]erver\s*:\s*lighttpd", icase:FALSE ) ) {
  concluded = "  " + chomp( concl );
  found = TRUE;
}

res = http_get_cache( item:url, port:port );
if( concl = egrep( string:res, pattern:"^\s*If you find a bug in this Lighttpd package, or in Lighttpd itself, please file a bug report on it\.", icase:FALSE ) ) {
  # nb: Minor formatting change for the reporting.
  concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
  if( concluded )
    concluded += '\n';
  concluded += "  " + chomp( concl );
  found = TRUE;
}

# nb:
# - Lighttpd seems to not have a standard "Error page" (unlike e.g. nginx) which we could use for a
#   detection
# - Lighttpd seems to be at least partly also running on Windows so no OS detection from the banner
#   for now (some basic OS detection from the default page is done in sw_http_os_detection.nasl)

if( found ) {

  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  version = "unknown";
  install = port + "/tcp";

  # nb: Currently unclear why the second pattern was added. No examples have been given in the past
  # so this was kept for now.
  vers = eregmatch( pattern:"[Ss]erver\s*:\s*lighttpd/([0-9.]+)(-[0-9.]+)?", string:banner, icase:FALSE );
  if( vers[1] ) {
    version = vers[1];
    if( vers[2] ) {
      vers[2] = ereg_replace( string:vers[2], pattern:"-", replace:"." );
      version = version + vers[2];
    }
  }

  set_kb_item( name:"lighttpd/detected", value:TRUE );
  set_kb_item( name:"lighttpd/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:lighttpd:lighttpd:" );
  if( ! cpe )
    cpe = "cpe:/a:lighttpd:lighttpd";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Lighttpd",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
