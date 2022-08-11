# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117570");
  script_version("2021-07-19T10:09:41+0000");
  script_tag(name:"last_modification", value:"2021-07-20 10:27:54 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-19 10:02:39 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache mod_ssl Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "apache_server_info.nasl", "apache_server_status.nasl",
                      "gb_apache_perl_status.nasl", "gb_apache_http_server_http_error_page_detect.nasl");
  script_mandatory_keys("mod_ssl_or_apache_status_info_error_pages/banner");

  script_xref(name:"URL", value:"https://httpd.apache.org/docs/2.4/mod/mod_ssl.html");

  script_tag(name:"summary", value:"HTTP based detection of Apache mod_ssl.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

pattern = "^Server\s*:.*mod_ssl";

# Server: Apache/1.3.29 (VxWorks) mod_ssl/2.8.16 OpenSSL/0.9.7d
# Server: Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-8+etch16 mod_perl/2.0.2 Perl/v5.8.8
# Server: Rapidsite/Apa-1.3.14 (Unix), Frontpage/4.0.4.3, mod_ssl/2.7.1, OpenSSL/0.9.5a
# Server: Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Server: HP Web Jetadmin/2.0.50 (Win32) mod_auth_sspi/1.0.1 mod_ssl/2.0.50 OpenSSL/0.9.6m
# Server: WebOTX_Web_Server/2.2.32 (Win32) PHP/5.2.2 mod_ssl/2.2.32 OpenSSL/1.0.2k
if( ! banner || ! found_banner = egrep( pattern:pattern, string:banner, icase:TRUE ) ) {

  # From apache_server_info.nasl, apache_server_status.nasl, gb_apache_perl_status.nasl or gb_apache_http_server_http_error_page_detect.nasl
  foreach infos( make_list( "server-info", "server-status", "perl-status", "apache_error_page" ) ) {

    info = get_kb_item( "www/" + infos + "/banner/" + port );
    if( info && found_banner = egrep( pattern:pattern, string:info, icase:TRUE ) ) {
      detected = TRUE;

      if( infos == "apache_error_page" ) {
        url = get_kb_item( "www/apache_error_page/banner/location/" + port );
        if( ! url )
          url = ""; # nb: Shouldn't happen but just to be sure...
      } else {
        url = "/" + infos;
      }

      conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      concluded = get_kb_item( "www/" + infos + "/banner/concluded/" + port );

      break;
    }
  }

  if( ! detected )
    exit( 0 );

} else {
  found_banner = chomp( found_banner );
  concluded = found_banner;
}

install = port + "/tcp";
version = "unknown";

vers = eregmatch( string:found_banner, pattern:"Server\s*:.*mod_ssl/([0-9.]+)", icase:TRUE );
if( vers[1] )
  version = vers[1];

set_kb_item( name:"apache/mod_ssl/detected", value:TRUE );
set_kb_item( name:"apache/mod_ssl/http/detected", value:TRUE );
set_kb_item( name:"apache/mod_python/http/detected", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_ssl:" );
if( ! cpe )
  cpe = "cpe:/a:apache:mod_ssl";

register_product( cpe:cpe, location:install, port:port, service:"www" );
log_message( data:build_detection_report( app:"Apache mod_ssl",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclurl,
                                          concluded:concluded ),
                                          port:port );
exit( 0 );