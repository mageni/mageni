###############################################################################
# OpenVAS Vulnerability Test
# $Id: nginx_detect.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100274");
  script_version("$Revision: 13859 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("nginx Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of nginx.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( banner && egrep( pattern:"Server: nginx", string:banner, icase:TRUE ) ) {
  vers = "unknown";
  installed = TRUE;

  version = eregmatch( string:banner, pattern:"Server: nginx/([0-9.]+)", icase:TRUE );

  if( ! isnull( version[1] ) ) {
    vers = version[1];
  } else {
    # Some configs are reporting the version in the banner if a index.php is called
    host = http_host_name( dont_add_port:TRUE );
    phpList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
    if( phpList ) phpFiles = make_list( phpList );

    if( phpFiles[0] ) {
      banner = get_http_banner( port:port, file:phpFiles[0] );
    } else {
      banner = get_http_banner( port:port, file:"/index.php" );
    }

    version = eregmatch( string:banner, pattern:"Server: nginx/([0-9.]+)", icase:TRUE );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
    }
  }
} else {
  # If the banner is hidden we still can try to see
  # if nginx is installed from the default 404 page
  url = "/non-existent.html";
  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  # This is the default page of nginx shipped on Debian/Ubuntu
  if( res =~ "^HTTP/1\.[01] [3-5].*" && "<hr><center>nginx</center>" >< res ) {
    vers = "unknown";
    installed = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: nginx" );
  }
}

if( installed ) {
  install = port + "/tcp";
  set_kb_item( name:"nginx/installed", value:TRUE );

  # Status page of the HttpStubStatusModule (https://nginx.org/en/docs/http/ngx_http_stub_status_module.html) module
  foreach ngnx_status( make_list( "/", "/basic_status", "/nginx_status" ) ) {
    res = http_get_cache( port:port, item:ngnx_status );
    if( res =~ "^HTTP/1\.[01] 200" &&
        ( egrep( string:res, pattern:"^Active connections: [0-9]+" ) || # Active connections: 4
          egrep( string:res, pattern:"^server accepts handled requests( request_time)?" ) || # "server accepts handled requests request_time" or only "server accepts handled requests"
          egrep( string:res, pattern:"^Reading: [0-9]+ Writing: [0-9]+ Waiting: [0-9]+" ) ) ) { # Reading: 0 Writing: 1 Waiting: 0
      extra = '\nOutput of the HttpStubStatusModule module available at ' + report_vuln_url( port:port, url:ngnx_status, url_only:TRUE );
      break;
    }
  }

  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:nginx:nginx:" );
  if( !cpe )
    cpe = 'cpe:/a:nginx:nginx';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"nginx",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:version[0],
                                            extra:extra ),
               port:port );
}

exit( 0 );
