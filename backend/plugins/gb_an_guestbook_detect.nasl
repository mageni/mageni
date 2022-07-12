###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_an_guestbook_detect.nasl 12013 2018-10-22 09:25:12Z cfischer $
#
# AN Guestbook Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800523");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 12013 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 11:25:12 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("AN Guestbook Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of AN Guestbook and
  sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/ag", "/ang", "/guestbook", "/anguestbook", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/index.php", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && "AG" >< res && "version" >< res ) {
    version = eregmatch( pattern:"AG(</a>)? - version ([0-9.]+)", string:res );
  } else {
    res = http_get_cache( item:dir + "/ang/index.php", port:port );
    if( res =~ "^HTTP/1\.[01] 200" && "Powered by" >< res && "ANG" >< res ) {
      version = eregmatch( pattern:"Powered by.*ANG(</a>)? ([0-9.]+)", string:res );
    }
  }

  if( version[2] ) {

    set_kb_item( name:"www/" + port + "/AN-Guestbook", value:version[2] );
    set_kb_item( name:"AN-Guestbook/detected", value:TRUE );

    cpe = build_cpe( value:version[2], exp:"^([0-9.]+)", base:"cpe:/a:an_guestbook:an_guestbook:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:an_guestbook:an_guestbook";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"An Guest Book",
                                              version:version[2],
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0]),
                                              port:port );

  }
}

exit( 0 );