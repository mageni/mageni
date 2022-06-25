###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_woltlab_burning_board_detect.nasl 10851 2018-08-09 08:19:54Z cfischer $
#
# WoltLab Burning Board (Lite) Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800936");
  script_version("2019-04-11T08:59:06+0000");
  script_tag(name:"last_modification", value:"2019-04-11 08:59:06 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("WoltLab Burning Board (Lite) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.woltlab.com/");

  script_tag(name:"summary", value:"This script detects the installed version of WoltLab Burning
  Board (Lite) and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/wbb", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/upload/index.php", port:port );
  res2 = http_get_cache( item:dir + "/index.php", port:port );
  res3 = http_get_cache( item:dir + "/acp/index.php", port:port );

  if( ( res =~ "^HTTP/1\.[01] 200" && "WoltLab Burning Board" >< res ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && ( "new WBB.Board." >< res2 || "<strong>Burning Board" >< res2 ) ) ||
      ( res3 =~ "^HTTP/1\.[01] 200" && ( ">WoltLab Burning Board" >< res3 || "new WCF.ACP.Menu" >< res3 ) ) ) {

    version = "unknown";

    ver = eregmatch( pattern:">Burning Board[&a-z; ]+(Lite )?([0-9.]+([A-Za-z0-9 ]+)?)<", string:res );
    ver[2] = ereg_replace( pattern:" ", replace:".", string:ver[2] );
    ver[2] = ereg_replace( pattern:"\.$", replace:"", string:ver[2] ); # nb: For some unknown reason the pattern above contained an empty space sometimes causing an trailing space added to the version.
    if( ! isnull( ver[2] ) ) {
      if( ver[1] == "Lite " ) {
        app_name = "WoltLab Burning Board Lite";
        base_cpe = "cpe:/a:woltlab:burning_board_lite";
      } else {
        app_name = "WoltLab Burning Board";
        base_cpe = "cpe:/a:woltlab:burning_board";
      }
      version = ver[2];
    } else {
      ver = eregmatch( pattern:"strong>Burning Board[&a-z; ]+(Lite )?([0-9.]+([A-Za-z0-9 ]+)?)<", string:res2 );
      ver[2] = ereg_replace( pattern:" ", replace:".", string:ver[2] );
      ver[2] = ereg_replace( pattern:"\.$", replace:"", string:ver[2] ); # nb: For some unknown reason the pattern above contained an empty space sometimes causing an trailing space added to the version.
      if( ! isnull( ver[2] ) ) {
        if( ver[1] == "Lite " ) {
          app_name = "WoltLab Burning Board Lite";
          base_cpe = "cpe:/a:woltlab:burning_board_lite";
        } else {
          app_name = "WoltLab Burning Board";
          base_cpe = "cpe:/a:woltlab:burning_board";
        }
        version = ver[2];
      } else {
        app_name = "WoltLab Burning Board";
        base_cpe = "cpe:/a:woltlab:burning_board";
        # <p align="center">WoltLab Burning Board 2.2.2 - Admin Control Panel</p>
        ver = eregmatch( pattern:"Burning Board ([0-9.]+([A-Za-z0-9 ]+)?)", string:res3 );
        ver[1] = ereg_replace( pattern:" ", replace:".", string:ver[1] );
        ver[1] = ereg_replace( pattern:"\.$", replace:"", string:ver[1] ); # nb: For some unknown reason the pattern above contained an empty space sometimes causing an trailing space added to the version.
        if( ! isnull( ver[1] ) )
          version = ver[1];
      }
    }

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"WoltLabBurningBoard/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)([0-9a-zA-Z.]+)?", base:base_cpe + ":" );
    if( isnull( cpe ) )
      cpe = base_cpe;

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:app_name,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );