###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_jetspeed_detect.nasl 8141 2017-12-15 12:43:22Z cfischer $
#
# Apache Jetspeed Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807647");
  script_version("$Revision: 8141 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:43:22 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:25 +0530 (Fri, 01 Apr 2016)");
  script_name("Apache Jetspeed Detection");

  script_tag(name:"summary", value:"Detection of Apache Jetspeed Open Portal.
  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");
  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

foreach dir( make_list_unique( "/", "/jetspeed", "/jetspeed/portal", cgi_dirs( port:port ) ) ) {

  install = dir;
  if(dir == "/") dir = "";

  rcvRes = http_get_cache( item:dir + "/", port:port );

  if( 'Welcome to Jetspeed' >< rcvRes && 'Login Portlet' >< rcvRes ) {

    version = "unknown";

    url = dir + "/about.psml";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    ver = eregmatch( pattern:"<h2>About the Jetspeed ([0-9.]+) Release</h2>", string:buf );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"www/" + port + "/jetspeed", value:version );
    set_kb_item( name:"Jetspeed/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:jetspeed:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:apache:jetspeed";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Apache Jetspeed",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
    exit(0);
  }
}
exit( 0 );
