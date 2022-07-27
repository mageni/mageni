###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_detect.nasl 11999 2018-10-21 09:01:06Z cfischer $
#
# Ecava IntegraXor Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804298");
  script_version("$Revision: 11999 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-21 11:01:06 +0200 (Sun, 21 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-19 16:21:28 +0530 (Mon, 19 May 2014)");
  script_name("Ecava IntegraXor Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 7131);
  script_require_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Ecava IntegraXor.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:7131 );

foreach dir( make_list_unique( "/", "/DEM0", "/project", "/ecava", "/integraxor", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/res?res/igres.dll/sys_about.html", port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  res2 = http_get_cache( item:dir + "/index.html", port:port );

  if( ">Powered by IntegraXor" >< res || "<title>ECAVA IntegraXor</title>" >< res2 || "system/scripts/igrX.js" >< res2 ) {

    version = "unknown";

    ver = eregmatch( pattern:">Version:.*>(IGX )?([0-9.]+)", string:res );
    if( ver[2] ) version = ver[2];

    set_kb_item( name:"www/" + port + "/Ecava/IntegraXor", value:version );
    set_kb_item( name:"EcavaIntegraXor/Installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ecava:integraxor:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ecava:integraxor';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Ecava IntegraXor",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );