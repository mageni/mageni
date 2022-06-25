###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_xenforo_detect.nasl 10851 2018-08-09 08:19:54Z cfischer $
#
# XenForo Forum Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111078");
  script_version("$Revision: 10851 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 10:19:54 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-01-17 09:00:00 +0100 (Sun, 17 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("XenForo Forum Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://xenforo.com/");

  script_tag(name:"summary", value:"This script detects an installed XenForo Forum
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/xenforo", "/xf", "/board", "/boards", cgi_dirs( port:port ) ) ) {

  found = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( ">Forum software by XenForo" >< res || "jQuery.extend(true, XenForo," >< res ) ) {
    found = TRUE;
  } else {
    res = http_get_cache(item:dir + "/", port:port );
    if( res =~ "^HTTP/1\.[01] 200" && ( ">Forum software by XenForo" >< res || "jQuery.extend(true, XenForo," >< res ) ) {
      found = TRUE;
    }
  }

  if( found ) {

    # TODO: Try to find an exposed version
    ver = "unknown";

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"xenforo/detected", value:TRUE );

    # CPE not reqistered yet
    cpe = "cpe:/a:xenforo:xenforo";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"XenForo",
                                              version:ver,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
