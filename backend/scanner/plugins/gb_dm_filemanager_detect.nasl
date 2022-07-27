###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dm_filemanager_detect.nasl 13217 2019-01-22 12:22:13Z cfischer $
#
# DM FileManager Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800818");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13217 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 13:22:13 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DM FileManager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of DM FileManager and
  DM Albums and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir1( make_list_unique( "/dm-filemanager", "/dmf", "/", cgi_dirs( port:port ) ) ) {

  install1 = dir1;
  if( dir1 == "/" ) dir1 = "";

  rcvRes1 = http_get_cache( item: dir1 + "/login.php", port:port );

  if( rcvRes1 =~ "HTTP/1.. 200" && "<title>Log In - DM FileManager" >< rcvRes1 ) {

    version1 = "unknown";

    ver1 = eregmatch( pattern:"DM FileManager[^?]+v([0-9]\.[0-9.]+)", string:rcvRes1 );
    if( ver1[1] != NULL ) version1 = ver1[1];

    set_kb_item( name:"dm-filemanager/detected", value:TRUE );

    cpe1 = build_cpe( value: version1, exp:"^([0-9.]+)", base:"cpe:/a:dutchmonkey:dm_filemanager:" );
    if( isnull( cpe1 ) )
      cpe1 = 'cpe:/a:dutchmonkey:dm_filemanager';

    register_and_report_cpe(app:"DM FileManager", ver:version1, concluded:ver1[0],
                            cpename:cpe1, insloc:install1, regPort:port);

    foreach dir2( make_list( "/dm-albums", "/albums" ) ) {

      install2 = dir1 + dir2;

      sndReq2 = http_get( item:dir1 + dir2 + "/readme.txt", port:port );
      rcvRes2 = http_keepalive_send_recv( data:sndReq2, port:port );

      if( rcvRes2 =~ "HTTP/1.. 200" && "DM Albums" >< rcvRes2 ) {

        version2 = "unknown";

        ver2 = eregmatch( pattern:"Stable tag: ([0-9.]+)", string:rcvRes2 );
        if( ver2[1] != NULL ) version2 = ver2[1];

        cpe2 = build_cpe( value: version2, exp:"^([0-9.]+)", base:"cpe:/a:dutchmonkey:dm_album:" );
        if( isnull( cpe2 ) )
          cpe2 = 'cpe:/a:dutchmonkey:dm_album';

        register_and_report_cpe(app:"DM Albums", ver:version2, concluded:ver2[0],
                            cpename:cpe2, insloc:install2, regPort:port);
      }
    }
  }
}

exit( 0 );
