##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitweaver_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Bitweaver Version Detection
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900355");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Bitweaver Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Bitweaver and
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

foreach dir( make_list_unique( "/bitweaver", "/bw", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/wiki/index.php", port:port );

  if( "Powered by bitweaver" >!< rcvRes ) {
    rcvRes = http_get_cache( item: dir + "/users/login.php", port:port );
  }

  if( rcvRes =~ "HTTP/1.. 200" && "Powered by bitweaver" >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"Version: (<strong>)?([0-9]\.[0-9.]+)", string:rcvRes );
    if( ver[2] != NULL ) version = ver[2];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/Bitweaver", value:tmp_version );
    set_kb_item( name:"Bitweaver/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:bitweaver:bitweaver:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:bitweaver:bitweaver';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Bitweaver",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );