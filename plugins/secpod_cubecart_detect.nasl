##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cubecart_detect.nasl 13109 2019-01-17 07:42:10Z ckuersteiner $
#
# CubeCart Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.900614");
  script_version("$Revision: 13109 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 08:42:10 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("CubeCart Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of CubeCart.

  The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.cubecart.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/cart", "/store", "/shop", "/cubecart", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && ( "Powered by CubeCart" >< rcvRes || ">CubeCart<" >< rcvRes ) ) {

    version = "unknown";

    tmpver = egrep( pattern:"CubeCart</a> [0-9.]+", string:rcvRes );
    ver = eregmatch( pattern:"> ([0-9.]+)", string:tmpver );
    if( ver[1] != NULL ) version = ver[1];

    set_kb_item( name:"cubecart/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cubecart:cubecart:" );
    if( !cpe )
      cpe = 'cpe:/a:cubecart:cubecart';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"CubeCart",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                 port:port) ;
  }
}

exit( 0 );
