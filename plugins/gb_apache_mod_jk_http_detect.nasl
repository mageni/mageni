# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800279");
  script_version("2021-07-13T07:25:02+0000");
  script_tag(name:"last_modification", value:"2021-07-13 11:35:30 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"creation_date", value:"2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Tomcat JK Connector (mod_jk) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "apache_server_info.nasl", "apache_server_status.nasl",
                      "gb_apache_perl_status.nasl", "gb_apache_http_server_http_error_page_detect.nasl");
  script_mandatory_keys("mod_jk_or_apache_status_info_error_pages/banner");

  script_xref(name:"URL", value:"https://tomcat.apache.org/connectors-doc/");

  script_tag(name:"summary", value:"HTTP based detection of Apache Tomcat JK Connector (mod_jk).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

pattern = "^Server\s*:.*mod_jk";

# Server: Apache/1.3.34 (Unix) mod_jk/1.2.15
# Server: Apache/2.0.63FTF (NETWARE) mod_jk/1.2.23 PHP/5.0.5
# Server: Apache/1.3.34 (Unix) mod_tsunami/3.0 mod_jk/1.2.15 mod_fastcgi/2.4.2 ApacheJServ/1.1.2 FrontPage/5.0.2.2510
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

vers = eregmatch( string:found_banner, pattern:"Server\s*:.*mod_jk/([0-9.]+)", icase:TRUE );
if( vers[1] )
  version = vers[1];

set_kb_item( name:"apache/mod_jk/detected", value:TRUE );
set_kb_item( name:"apache/mod_jk/http/detected", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_jk:" );
if( ! cpe )
  cpe = "cpe:/a:apache:mod_jk";

register_product( cpe:cpe, location:install, port:port, service:"www" );
log_message( data:build_detection_report( app:"Apache Tomcat JK Connector (mod_jk)",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclurl,
                                          concluded:concluded ),
                                          port:port );
exit( 0 );