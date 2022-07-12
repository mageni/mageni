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
  script_oid("1.3.6.1.4.1.25623.1.0.100129");
  script_version("2021-07-07T08:14:44+0000");
  script_tag(name:"last_modification", value:"2021-07-07 08:14:44 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache mod_perl Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "apache_server_info.nasl", "apache_server_status.nasl",
                      "gb_apache_perl_status.nasl");
  script_mandatory_keys("mod_perl_or_apache_status_info_pages/banner");

  script_xref(name:"URL", value:"https://perl.apache.org/");

  script_tag(name:"summary", value:"HTTP based detection of Apache mod_perl.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

pattern = "^Server\s*:.*mod_perl";

# Server: Apache/2.2.31 (Unix) mod_perl/2.0.4 Perl/v5.8.9
# Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_perl/2.0.11 Perl/v5.16.3
# Server: Apache/2.4.25 (Debian) PHP/5.6.40-0+deb8u4 mod_python/3.3.1 Python/2.7.13 OpenSSL/1.0.2u mod_perl/2.0.10 Perl/v5.24.1
# Server: Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-8+etch16 mod_perl/2.0.2 Perl/v5.8.8
# Server: Apache-AdvancedExtranetServer/2.0.53 (Mandrakelinux/PREFORK-9mdk) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/4.3.10 mod_perl/1.999.21 Perl/v5.8.6
# Server: Apache/2.4.18 (Ubuntu) OpenSSL/1.0.2g SVN/1.9.3 Phusion_Passenger/5.0.27 mod_perl/2.0.9 Perl/v5.22.1
if( ! concl = egrep( pattern:pattern, string:banner, icase:TRUE ) ) {

  # From apache_server_info.nasl, apache_server_status.nasl or gb_apache_perl_status.nasl
  foreach infos( make_list( "server-info", "server-status", "perl-status" ) ) {

    info = get_kb_item( "www/" + infos + "/banner/" + port );
    if( info && concl = egrep( pattern:pattern, string:info, icase:TRUE ) ) {
      detected = TRUE;
      conclurl = http_report_vuln_url( port:port, url:"/" + infos, url_only:TRUE );
      break;
    }
  }

  if( ! detected )
    exit( 0 );
}

concl = chomp( concl );
install = "/";
version = "unknown";

vers = eregmatch( string:concl, pattern:"Server\s*:.*mod_perl/([0-9.]+)", icase:TRUE );
if( vers[1] )
  version = vers[1];

set_kb_item( name:"apache/mod_perl/detected", value:TRUE );
set_kb_item( name:"apache/mod_perl/http/detected", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:mod_perl:" );
if( ! cpe )
  cpe = "cpe:/a:apache:mod_perl";

register_product( cpe:cpe, location:install, port:port, service:"www" );
log_message( data:build_detection_report( app:"Apache mod_perl",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclurl,
                                          concluded:concl ),
                                          port:port );
exit( 0 );