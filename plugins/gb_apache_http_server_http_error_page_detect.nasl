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
  script_oid("1.3.6.1.4.1.25623.1.0.117544");
  script_version("2021-07-09T09:46:35+0000");
  script_tag(name:"last_modification", value:"2021-07-09 11:26:32 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-09 09:17:42 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache HTTP Server Detection (HTTP Error Page)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP error-page based detection of the Apache HTTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

pattern1 = "<address>(.+) Server at .+ Port [0-9]+</address>";
pattern2 = "\s*<span>(Apache[^<]*)</span>";

foreach url( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

  res = http_get_cache( item:url, port:port, fetch404:TRUE );

  # If the banner was hidden or was changed by e.g. mod_security but the default error
  # page still exists. e.g.:
  # <address>Apache/2.4.10 (Debian) Server at 192.168.9.217 Port 80</address>
  # but also:
  # <address>MyChangedBanner Server at 192.168.9.217 Port 80</address>
  #
  # nb: The above default error page was seen on Debian / Ubuntu but e.g SLES 15 has a
  # different one we need to cover as well:
  # <h2>Error 403</h2>
  # <address>
  #   <a href="/">127.0.0.1</a><br />
  #   <span>Apache</span>
  # </address>
  # or:
  # <address>
  #   <a href="/">192.168.9.93</a><br />
  #   <span>Apache/2.4.43 (Linux/SUSE) OpenSSL/1.1.1d</span>
  # </address>

  if( res && res =~ "^HTTP/1\.[01] [3-5][0-9]{2}" ) {

    if( concl = egrep( string:res, pattern:"^" + pattern1, icase:TRUE ) ) {
      error_page_found = TRUE;
      kb_banner = eregmatch( string:concl, pattern:pattern1, icase:TRUE );
    } else if( res =~ "<address>.*<a href=.+</a>.*<span>Apache[^<]*</span>.*</address>" ) {
      error_page_found = TRUE;
      concl = egrep( string:res, pattern:"^" + pattern2, icase:TRUE );
      if( concl )
        kb_banner = eregmatch( string:concl, pattern:pattern2, icase:TRUE );
    }

    if( error_page_found ) {
      set_kb_item( name:"apache/http_server/error_page/detected", value:TRUE );
      set_kb_item( name:"www/apache_error_page/banner/location/" + port, value:url );

      if( kb_banner[1] )
        # nb: Saving it into this format for all VTs checking something like "Server\s*:\s*Apache".
        set_kb_item( name:"www/apache_error_page/banner/" + port, value:"Server: " + kb_banner[1] );

      break;
    }
  }
}

exit( 0 );