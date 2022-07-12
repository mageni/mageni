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
  script_oid("1.3.6.1.4.1.25623.1.0.117545");
  script_version("2021-07-09T11:56:48+0000");
  script_tag(name:"last_modification", value:"2021-07-12 10:11:17 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-09 11:23:30 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("nginx Detection (HTTP Error Page)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP error-page based detection of nginx.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

# nb: No need to run if we have a full banner like e.g.:
# Server: nginx/1.14.2
# In this case we don't get any additional / more detailed info from the error page and just can jump out.
if( banner && egrep( string:banner, pattern:"^Server\s*:\s*nginx/[0-9.]+", icase:TRUE ) )
  exit( 0 );

# If the banner is hidden we still can try to see if nginx is installed from the default error pages
# like e.g. for 301 redirects (e.g. the redirect might happen on the landing page) or 404 not found pages.
# nb: Some reverse proxy setups might only expose the version on these pages (see examples listed below).

foreach url( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

  res = http_get_cache( port:port, item:url, fetch404:TRUE );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]{3}" )
    continue;

  # Few examples from Debian/Ubuntu (other Distros might use the same):
  #
  #<html>
  #<head><title>301 Moved Permanently</title></head>
  #<body bgcolor="white">
  #<center><h1>301 Moved Permanently</h1></center>
  #<hr><center>nginx/1.14.2</center>
  #</body>
  #</html>
  #
  # or:
  #
  #<html>
  #<head><title>404 Not Found</title></head>
  #<body bgcolor="white">
  #<center><h1>404 Not Found</h1></center>
  #<hr><center>nginx/1.10.3</center>
  #</body>
  #</html>
  #
  # but also without the version (other parts are the same):
  #
  #<hr><center>nginx</center>
  #
  # and also with Distro specific strings:
  #
  #<hr><center>nginx/1.14.0 (Ubuntu)</center>

  if( res =~ "<html>\s*<head>\s*<title>[^<]+</title>\s*</head>\s*<body" && res =~ "<hr>\s*<center>nginx[^<]*</center>\s*</body>\s*</html>" ) {

    set_kb_item( name:"nginx/error_page/detected", value:TRUE );
    set_kb_item( name:"www/nginx_error_page/banner/location/" + port, value:url );

    kb_banner = eregmatch( string:res, pattern:"<hr>\s*<center>(nginx[^<]*)</center>", icase:FALSE );
    if( kb_banner[1] ) {
      # nb: Saving it into this format for all VTs checking something like "Server\s*:\s*nginx".
      set_kb_item( name:"www/nginx_error_page/banner/" + port, value:"Server: " + kb_banner[1] );
    }

    break;
  }
}

exit( 0 );