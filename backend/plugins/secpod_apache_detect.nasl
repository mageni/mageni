###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_detect.nasl 10290 2018-06-21 14:28:42Z cfischer $
#
# Apache Web Server Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900498");
  script_version("$Revision: 10290 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 16:28:42 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Web Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "apache_server_info.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Apache Web Server

  The script detects the version of Apache HTTP Server on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

# Just the default server banner without catching e.g. Apache-Tomcat
if( banner && "Apache" >< banner && "Apache-" >!< banner ) {

  version = "unknown";
  installed = TRUE;

  vers = eregmatch( pattern:"Server: Apache/([0-9]\.[0-9]+\.[0-9][0-9]?)", string:banner );
  if( ! isnull( vers[1] ) ) version = chomp( vers[1] );
}

if( ! version || version == "unknown" ) {

  # From apache_server_info.nasl
  server_info = get_kb_item( "www/server-info/banner/" + port );

  if( server_info ) {

    url = "/server-info";
    version = "unknown";
    installed = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"Server: Apache/([0-9]\.[0-9]+\.[0-9][0-9]?)", string:server_info );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
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
    installed = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<address>Apache/([0-9]\.[0-9]+\.[0-9][0-9]?).* Server at .* Port ([0-9.]+)</address>", string:res );
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
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # From the apache docs, this is only providing the major release (e.g. 2.4)
  if( res =~ "^HTTP/1\.[01] 200" && "<title>Apache HTTP Server Version" >< res && "Documentation - Apache HTTP Server" >< res ) {

    version = "unknown";
    installed = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:"<title>Apache HTTP Server Version ([0-9]\.[0-9]+).*Documentation - Apache HTTP Server.*</title>", string:res );

    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( installed ) {

  install = port + "/tcp";

  set_kb_item( name:"www/" + port + "/Apache", value:version );
  set_kb_item( name:"apache/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:http_server:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:apache:http_server";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Apache",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
