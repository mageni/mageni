###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wideimage_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# WideImage Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805693");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-08-03 12:36:53 +0530 (Mon, 03 Aug 2015)");
  script_name("WideImage Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  WideImage.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/WideImage-master", "/wideimage", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach url( make_list( "/index.php", "/doc/index.html", "/composer.json" ) ) {

    path = dir + url;

    rcvRes = http_get_cache( item:path, port:port );

    if( rcvRes =~ "HTTP/1.. 200" && ( "<title>WideImage" >< rcvRes || rcvRes =~ "homepage.*wideimage" ) ) {

      installed = TRUE;

      version = eregmatch( pattern:"(WideImage.v|((V|v)ersion.:..))([0-9.]+)", string:rcvRes );
      if( version[4] ) {
        wideVersion = version[4];
      } else {
        continue;
      }
    }
  }

  if( installed ) {

    ##If version information not available set to unknown
    if( ! wideVersion ) wideVersion = "Unknown";

    set_kb_item( name:"www/" + port + "/WideImage", value:wideVersion );
    set_kb_item( name:"WideImage/installed", value:TRUE );

    cpe = build_cpe( value:wideVersion, exp:"^([0-9.]+)", base:"cpe:/a:wideimage:wideimage:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:wideimage:wideimage";

    register_product( cpe:cpe, location:install, port:port );
    log_message( data:build_detection_report( app:"WideImage",
                                              version:wideVersion,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );