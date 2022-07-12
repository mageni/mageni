###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_prochatrooms_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Pro Chat Rooms Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900330");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pro Chat Rooms Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Pro Chat Rooms
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/prochatrooms", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/help/index.php", port:port );

  if( egrep( pattern:"^HTTP/.* 200 OK", string:rcvRes ) &&
      egrep( pattern:"<title>Pro Chat Rooms", string:rcvRes ) ) {

    version = "unknown";

    pcrVer = eregmatch( pattern:"Pro Chat Rooms - User Help (Section \()?v([0-9.]+)", string:rcvRes );

    if( ! isnull( pcrVer[2] ) ) version = pcrVer[2];

    set_kb_item( name:"www/"+ port + "/ProChatRooms", value:version );
    set_kb_item( name:"ProChatRooms/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:pro_chat_rooms:pro_chat_rooms:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:pro_chat_rooms:pro_chat_rooms';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Pro Chat Room",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:pcrVer[0] ),
                                              port:port );
  }
}

exit( 0 );