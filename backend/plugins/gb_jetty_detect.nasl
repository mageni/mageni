###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_detect.nasl 12710 2018-12-07 19:40:26Z cfischer $
#
# Jetty Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800953");
  script_version("$Revision: 12710 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 20:40:26 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Jetty Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Jetty Web Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );

if( _banner = egrep( pattern:"^Server: Jetty", string:banner, icase:TRUE ) ) {

  version   = "unknown";
  installed = TRUE;
  concluded = _banner;

  # Server: Jetty(9.2.14.v20151106)
  # Server: Jetty(6.1.x)
  # Server: Jetty(6.1.3)
  # Server: Jetty(9.2.z-SNAPSHOT)
  # Server: Jetty(winstone-2.8)
  # Server: Jetty(9.4.z-SNAPSHOT)
  # Server: Jetty(8.y.z-SNAPSHOT)
  ver = eregmatch( pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string:_banner );

  if( ! isnull( ver[1] ) ) {
    if( ! isnull( ver[2] ) ) {
      ver[2] = ereg_replace( pattern:"^v", string:ver[2], replace:"" );
      if( ver[1] =~ "\.$" )
        version = ver[1] + ver[2];
      else
        version = ver[1] + "." + ver[2];
    } else {
      ver[1] = ereg_replace( pattern:"\.$", string:ver[1], replace:"" );
      version = ver[1];
    }
  }
}

if( ! installed ) {

  # If banner is changed / hidden but default error page still exists.
  url = "/non-existent.html";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  # <hr><a href="http://eclipse.org/jetty">Powered by Jetty:// 9.4.10.v20180503</a><hr/>
  # nb: 404 page sometimes doesn't contain a version so just setting it as "installed" in that case.
  if( res =~ "^HTTP/1\.[01] [3-5].*" && ( "<small>Powered by Jetty://</small>" >< res || ">Powered by Jetty:// " >< res ) ) {
    installed = TRUE;
    version   = "unknown";
    conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );

    ver = eregmatch( pattern:">Powered by Jetty:// ([0-9.]+)v([0-9]+)", string:res );
    if( ! isnull( ver[1] ) || ! isnull( ver[2] ) ) {
      concluded = ver[0];
      version = ver[1] + ver[2];
    }
  }
}

if( installed ) {

  install = port + "/tcp";
  set_kb_item( name:"www/" + port + "/Jetty", value:version );
  set_kb_item( name:"Jetty/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:eclipse:jetty:" );
  if( ! cpe )
    cpe = "cpe:/a:eclipse:jetty";

   register_product( cpe:cpe, location:install, port:port, service:"www" );
   log_message( data:build_detection_report( app:"Jetty Web Server",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concluded:concluded,
                                             concludedUrl:conclUrl ),
                                             port:port );
}

exit( 0 );