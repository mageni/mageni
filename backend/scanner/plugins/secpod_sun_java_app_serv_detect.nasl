###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_app_serv_detect.nasl 12985 2019-01-09 07:04:34Z cfischer $
#
# Sun Java System Application Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By Veerendra G <veerendragg@secpod.com>
# date update: 2010/02/05
# Added logic to detect Sun Java System Application Server Version from
# Response headers
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
  script_oid("1.3.6.1.4.1.25623.1.0.900200");
  script_version("$Revision: 12985 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 08:04:34 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun Java System Application Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Application Server and sets
  the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
res = http_get_cache( item:"/", port:port );
if( ! res )
  exit( 0 );

## Sun Java System Application Server Formerly known as
## Sun ONE Application Server and now it is known as
## Sun GlassFish Enterprise Server
## http://www.sun.com/software/products/appsrvr/index.jsp

## Server: Sun-ONE-Application-Server/7.0.0_11
## Server: Sun-Java-System-Application-Server/7 2004Q2UR6
## Sun Java System Application Server Platform Edition 9.0_01

vers = eregmatch( pattern:"Server: Sun[- a-zA-Z]+Application[- ]Server/?([a-zA-Z0-9._ ]+)", string:res );
if( vers[1] ) {
  version = appservVer[1] - " Platform Edition ";
  version = chomp( version );
  found = TRUE;
} else if( egrep( pattern:"Sun Java System Application Server .*", string:res ) ) {

  vers = eregmatch( pattern:"Platform Edition ([0-9.]+)", string:res );
  if( vers[1] ) {
    version = vers[1];
    found = TRUE;
  }
}

if( found ) {
  set_kb_item( name:"sun_java_appserver/installed", value:TRUE );
  set_kb_item( name:"glassfish_or_sun_java_appserver/installed", value:TRUE );

  register_and_report_cpe( app:"Sun Java Application Server", ver:version, concluded:vers[0],
                           base:"cpe:/a:sun:java_system_application_server:",
                           expr:"^([0-9.]+)", insloc:"/", regService:"www" );
}

exit( 0 );