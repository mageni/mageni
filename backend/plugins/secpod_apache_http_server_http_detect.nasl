# Copyright (C) 2009 SecPod
# New NASL / detection code since 2014 Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900498");
  script_version("2021-02-25T13:36:35+0000");
  script_tag(name:"last_modification", value:"2021-02-26 11:25:03 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache HTTP Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_get_http_banner.nasl", "apache_server_info.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add script_mandatory_keys("apache/http_server/server_or_server-info/banner");
  # because the VT is also doing a detection based on a 404 error page.

  script_tag(name:"summary", value:"HTTP based detection of the Apache HTTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

# Just the default server banner without catching e.g. Apache-Tomcat
if( banner && "Apache" >< banner && "Apache-" >!< banner ) {

  version = "unknown";
  detected = TRUE;

  vers = eregmatch( pattern:"Server\s*:.*Apache/([0-9.]+(-(alpha|beta))?)", string:banner, icase:TRUE );
  if( ! isnull( vers[1] ) )
    version = vers[1];
}

if( ! version || version == "unknown" ) {

  # From apache_server_info.nasl
  server_info = get_kb_item( "www/server-info/banner/" + port );
  if( server_info ) {

    url = "/server-info";
    version = "unknown";
    detected = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"Server\s*: .*(Rapidsite/Apa|Apache)/([0-9.]+(-(alpha|beta))?)", string:server_info, icase:TRUE );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] + "/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] );
    }
  }
}

if( ! version || version == "unknown" ) {

  url = "/non-existent.html";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  # If banner is changed by e.g. mod_security but default error page still exists
  if( res =~ "^HTTP/1\.[01] [3-5].*" && res =~ "<address>.* Server at .* Port.*</address>" ) {

    version = "unknown";
    detected = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<address>Apache/([0-9.]+(-(alpha|beta))?).* Server at .* Port ([0-9.]+)</address>", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( ! version || version == "unknown" ) {

  url = "/manual/en/index.html";
  res = http_get_cache( item:url, port:port );

  # From the apache docs, this is only providing the major release (e.g. 2.4)
  if( res =~ "^HTTP/1\.[01] 200" && "<title>Apache HTTP Server Version" >< res && "Documentation - Apache HTTP Server" >< res ) {

    version = "unknown";
    detected = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<title>Apache HTTP Server Version ([0-9]\.[0-9]+).*Documentation - Apache HTTP Server.*</title>", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( detected ) {

  install = port + "/tcp";

  set_kb_item( name:"apache/http_server/detected", value:TRUE );
  set_kb_item( name:"apache/http_server/http/detected", value:TRUE );
  set_kb_item( name:"apache/http_server/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclUrl + "#---#" );
}

exit( 0 );
