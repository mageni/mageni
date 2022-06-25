###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_detect.nasl 8215 2017-12-21 11:46:59Z cfischer $
#
# Sun/Oracle Web Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By Veerendra G <veerendragg@secpod.com>
# date update: 2010/01/20
# Added for loop to check for all the ports (80, 8800, 8989, 8888)
#
# Updated By Sooraj KS <kssooraj@secpod.com>
# date update: 2012/07/03
# Updated to detect Oracle iPlanet Web Server
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
  script_oid("1.3.6.1.4.1.25623.1.0.800810");
  script_version("$Revision: 8215 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 12:46:59 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun/Oracle Web Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8080, 8800, 8989, 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Sun/Oracle Web Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

jswsPort = get_http_port( default:80 );
banner = get_http_banner( port:jswsPort );
if( ! banner || banner == "" ) exit( 0 );

if( "erver: Sun-" >< banner || "erver: Oracle-iPlanet-Web-Server" >< banner ) {

  url = "/admingui/version/copyright";
  req = http_get( item:url, port:jswsPort );
  body = http_keepalive_send_recv( port: jswsPort, data:req );

  if( "Sun Java System Web Server" >< body || "Sun-Java-System-Web-Server" >< body ) {

    app = "Sun Java System Web Server";
    version = eregmatch( pattern:"Sun[ |-]Java[ |-]System[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:body );

    if( version[1] ) {
      set_kb_item( name:"Sun/JavaSysWebServ/Ver", value:version[1] );
      set_kb_item( name:"Sun/JavaSysWebServ/" + jswsPort + "/Ver", value:version[1] );
    }

    set_kb_item( name:"Sun/JavaSysWebServ/Port", value:jswsPort );
    set_kb_item( name:"java_system_web_server/installed", value:TRUE );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_web_server:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sun:java_system_web_server';

  } else if( "Oracle iPlanet Web Server" >< body || "Oracle-iPlanet-Web-Server" >< body ) {

    app = "Oracle iPlanet Web Server";
    version = eregmatch( pattern:"Oracle[ |-]iPlanet[ |-]Web[ |-]Server[ |/]([0-9.]+)", string:body );

    if( version[1] ) {
      set_kb_item( name:"Oracle/iPlanetWebServ/Ver", value:version[1] );
      set_kb_item( name:"Oracle/iPlanetWebServ/" + jswsPort + "/Ver", value:version[1] );
    }

    set_kb_item( name:"Oracle/iPlanetWebServ/Port", value:jswsPort );
    set_kb_item( name:"oracle_iplanet_web_server/installed", value:TRUE );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:iplanet_web_server:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sun:iplanet_web_server';

  } else if( "Sun-ONE-Web-Server" >< banner ) {

    app = "Sun ONE Web Server";
    version = eregmatch( pattern:"Sun-ONE-Web-Server/([0-9.]+)", string:banner );

    if( version[1] ) {
      set_kb_item( name:"Sun/OneWebServ/Ver", value:version[1] );
      set_kb_item( name:"Sun/OneWebServ/" + jswsPort + "/Ver", value:version[1] );
    }

    set_kb_item( name:"Sun/OneWebServ/Port", value:jswsPort );
    set_kb_item( name:"sun_one_web_server/installed", value:TRUE );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:one_web_server:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sun:one_web_server';

  } else {
    app = "Unknown Sun Web Server";
    cpe = 'cpe:/a:sun:unknown_web_server';
  }

  register_product( cpe:cpe, location:jswsPort + "/tcp", port:jswsPort );

  log_message( data:build_detection_report( app:app,
                                            version:version[1],
                                            install:jswsPort + "/tcp",
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:jswsPort );
}

exit( 0 );
