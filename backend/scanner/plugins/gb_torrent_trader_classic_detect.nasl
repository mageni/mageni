###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_torrent_trader_classic_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# TorrentTrader Classic Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800525");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("TorrentTrader Classic Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.torrenttrader.org/");

  script_tag(name:"summary", value:"This script detects the installed version of TorrentTrader
  Classic and sets the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/ttc", "/", "/torrenttrader", "/torrent", "/tracker", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  installed = FALSE;
  version = "unknown";

  sndReq = http_get( item:dir + "/upload/account-login.php", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  if( rcvRes =~ "HTTP/1.. 200" && "TorrentTrader Classic" >< rcvRes ) {

    installed = TRUE;

    ver = eregmatch( pattern:"Classic ([a-zA-z]+)? ?v([0-9.]+)", string:rcvRes );
    if( ver[2] != NULL ) {
      if( ver[1] != NULL ) {
        version = ver[2] + "." + ver[1];
      } else {
        version = ver[2];
      }
    }
  }

  if( version == "unknown" ) {

    rcvRes = http_get_cache( item:dir + "/index.php", port:port );

    if( egrep( pattern: "Powered by TorrentTrader Classic ([a-zA-z]+)? ?v([0-9.]+).*www.torrenttrader.org", string:rcvRes, icase:TRUE ) ) {

      installed = TRUE;

      ver = eregmatch( pattern: "TorrentTrader Classic ([a-zA-z]+)? ?v([0-9.]+)", string:rcvRes );
      if( ver[2] != NULL ) {
        if( ver[1] != NULL ) {
          version = ver[2] + "." + ver[1];
        } else {
          version = ver[2];
        }
      }
    }
  }

  if( installed ) {

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port  + "/TorrentTraderClassic", value:tmp_version );
    set_kb_item( name:"torrenttraderclassic/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:torrenttrader:torrenttrader_classic:" );
    if( isnull( cpe ) ) {
      cpe = build_cpe( value:version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:torrenttrader:torrenttrader_classic:" );
      if( isnull( cpe ) ) {
        cpe = 'cpe:/a:torrenttrader:torrenttrader_classic';
      }
    }

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"TorrentTrader Classic",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );