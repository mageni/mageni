###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_fusion_detect.nasl 10764 2018-08-03 14:25:59Z cfischer $
#
# Detection of PHP-Fusion Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900612");
  script_version("$Revision: 10764 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-03 16:25:59 +0200 (Fri, 03 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detection of PHP-Fusion Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.php-fusion.co.uk");

  script_tag(name:"summary", value:"Detection of PHP-Fusion.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

function _SetCpe( version, tmp_version, dir ) {

  set_kb_item( name:"www/" + port + "/php-fusion", value: tmp_version );
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:php-fusion:php-fusion:" );

  if( isnull( cpe ) )
    cpe = "cpe:/a:php-fusion:php-fusion";

  register_product( cpe:cpe, location:dir, port:port );
  log_message( data:build_detection_report( app:"PHP-Fusion",
                                            version:version,
                                            install:dir,
                                            cpe:cpe,
                                            concluded:version ),
                                            port:port );
}

foreach dir( make_list_unique( "/", "/php-fusion", "/phpfusion", cgi_dirs( port:port ) ) ) {

  flag = FALSE;
  tmp_version= "";
  version= "";

  install = dir;
  if( dir == "/" ) dir = "";

  foreach subdir( make_list( "", "/files", "/php-files" ) ) {

    res = http_get_cache( item:dir + subdir + "/news.php", port:port );

    if( res =~ "^HTTP/1\.[01] 200" && ( "PHP-Fusion Powered" >< res ||
        ">Powered by <a href='https://www.php-fusion.co.uk'>PHP-Fusion</a>" >< res ) ) {

      set_kb_item( name:"php-fusion/installed", value:TRUE );
      flag = TRUE;

      matchline = egrep( pattern:"></a> v[0-9.]+", string:res );
      matchVersion = eregmatch( pattern:"> v([0-9.]+)", string:matchline );
      if( matchVersion[1] != NULL ) {
        version = matchVersion[1];
        tmp_version = matchVersion[1] + " under " + install;
      }
      if( version ) {
        _SetCpe( version:version, tmp_version:tmp_version, dir:install );
      }
    }
  }

  if( ! version ) {

    res = http_get_cache( item:dir + "/readme-en.html", port:port );

    if( res =~ "^HTTP/1\.[01] 200" && "PHP-Fusion Readme" >< res ) {

      set_kb_item( name:"php-fusion/installed", value:TRUE );
      flag = TRUE;

      matchline = egrep( pattern:"Version:</[a-z]+> [0-9.]+", string:res );
      matchVersion = eregmatch( pattern:"> ([0-9.]+)", string:matchline );

      if( matchVersion[1] != NULL ) {
        version = matchVersion[1];
        tmp_version = matchVersion[1] + " under " + install;
      }

      if( version ) {
        _SetCpe( version:version, tmp_version:tmp_version, dir:install );
      }
    }
  }

  if( ! version && flag ) {
    version = "Unknown";
    tmp_version = version + " under " + install;
    _SetCpe( version:version, tmp_version:tmp_version, dir:install );
  }
}

exit( 0 );
