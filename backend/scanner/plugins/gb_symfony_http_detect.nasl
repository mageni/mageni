###############################################################################
# OpenVAS Vulnerability Test
#
# Sensiolabs Symfony Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107323");
  script_version("2019-05-23T07:09:57+0000");
  script_tag(name:"last_modification", value:"2019-05-23 07:09:57 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sensiolabs Symfony Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8000, 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote host and attempts
  to detect the presence of Sensiolabs Symfony.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8000 );

# Some installations aren't fully configured and only show a welcome message including the version
buf = http_get_cache( item:"/", port:port );

if( buf =~ "^HTTP/1\.[01] 200" && buf =~ "<h1><span>Welcome to</span> Symfony [0-9.]+</h1>" ) {

  install = "/";
  version = "unknown";
  found = TRUE;

  vers = eregmatch( pattern:'Symfony ([0-9.]+)</h1>', string:buf );
  if( vers[1] ) {
    version = vers[1];
  }
  conclUrl = report_vuln_url( port:port, url:"/", url_only:TRUE );
  set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
}

# nb: This is only available at /_profiler
buf = http_get_cache( item:"/_profiler/latest", port:port );

if( buf =~ "^HTTP/1\.[01] 200" && ( "<title>Symfony Profiler</title>" >< buf || "https://symfony.com/search" >< buf ) ) {

  install = "/";
  version = "unknown";
  found = TRUE;

  url = "/_profiler/latest?ip=&limit=1";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  match = eregmatch( string:buf, pattern:"<dt>Token</dt>.*<dd>([0-9a-z]+)</dd>", icase:TRUE );

  if( match[1] ) {
    url = "/_profiler/" + match[1] + "?panel=config";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( "<h2>Symfony Configuration</h2>" >< buf ) {
      #   <span class="value">3.2.13</span>
      vers = eregmatch( pattern:'value">([0-9.]+)</span>', string:buf );
      if( vers[1] ) {
        version = vers[1];
      }
    }
  }
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
}

foreach dir( make_list( "/", "/symfony", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  # nb: /web/app_dev.php could be exposed in various subdirs
  url = dir + "/web/app_dev.php/_configurator/step/0";
  buf = http_get_cache( item:url, port:port );
  if( buf =~ "^HTTP/1\.[01] 200" && "Symfony Standard Edition" >< buf ) {

    version = "unknown";
    found = TRUE;
    vers = eregmatch( string:buf, pattern:"Symfony Standard Edition v\.([0-9.]+)", icase:TRUE );
    if( vers[1] ) {
      version = vers[1];
    }
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
  }

  # same as app_dev.php above
  url = dir + "/app.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && "Framework Symfony Version" >< buf ) {

    version = "unknown";
    found = TRUE;
    vers = eregmatch( string:buf, pattern:"Framework Symfony Version ([0-9.]+)", icase:TRUE );
    if( vers[1] ) {
      version = vers[1];
    }
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
  }

  url = dir + "/login";
  buf = http_get_cache( item:url, port:port );

  vers = eregmatch( string:buf, pattern:'box-symfony-version">.*Symfony ([0-9.]+)', icase:TRUE );
  if( vers[1] ) {
    version = vers[1];
    found = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
  }

  url = dir + "/src/Symfony/Component/Console/CHANGELOG.md";
  req = http_get( item:url, port:port);
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE) ;

  if( buf =~ "^CHANGELOG" && egrep( string:buf, pattern:"^=========" ) && vers = egrep( string:buf, pattern:"^([0-9.]+)" ) ) {
    vers = eregmatch( string:vers, pattern:"^([0-9.]+)");
    version = vers[1];
    found = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    set_kb_item( name:"symfony/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl );
  }
}

if( found ) {
  set_kb_item( name:"symfony/detected", value:TRUE );
  set_kb_item( name:"symfony/http/detected", value:TRUE );
  set_kb_item( name:"symfony/http/port", value:port );
}

exit( 0 );
