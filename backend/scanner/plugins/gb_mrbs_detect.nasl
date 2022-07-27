###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mrbs_detect.nasl 7874 2017-11-22 19:39:38Z cfischer $
#
# Meeting Room Booking System Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800949");
  script_version("$Revision: 7874 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 20:39:38 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Meeting Room Booking System Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Meeting Room
  Booking System and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/mrbs", "/mrbs1261", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/web/help.php", port:port );

  if( rcvRes !~ "HTTP/1\.[01] 200" || ( "About MRBS" >!< rcvRes && "Meeting Room Booking System" >!< rcvRes ) ) {

    rcvRes = http_get_cache( item:dir + "/help.php", port:port );

    if( rcvRes !~ "HTTP/1\.[01] 200" || ( "About MRBS" >!< rcvRes && "Meeting Room Booking System" >!< rcvRes ) ) {
      continue;
    }
  }

  set_kb_item( name:"MRBS/installed", value:TRUE );
  version = "unknown";
  ver = eregmatch( pattern:"MRBS ([0-9.]+).?([a-zA-Z]+([0-9]+)?)?", string:rcvRes );

  if( ver[1] != NULL ) {
    if( ver[2] != NULL ) {
      version = ver[1] + "." + ver[2];
    } else {
      version = ver[1];
    }
  }

  cpe = build_cpe( value: version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:john_beranek:meeting_room_booking_system:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:john_beranek:meeting_room_booking_system";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Meeting Room Booking System",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
