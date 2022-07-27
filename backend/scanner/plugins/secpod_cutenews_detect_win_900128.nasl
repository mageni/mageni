##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cutenews_detect_win_900128.nasl 11885 2018-10-12 13:47:20Z cfischer $
# Description: CuteNews Version Detection for Windows
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900128");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_name("CuteNews Version Detection for Windows");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Deprecated: This NVT has been replaced by NVT 'CuteNews Detection' (OID:
1.3.6.1.4.1.25623.1.0.100105).

 This script find the CuteNews installed version of Windows and
 saves the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cutenews", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && "CuteNews" >< rcvRes ) {

    version = "unknown";

    ver = egrep( pattern:"CuteNews v[0-9.]+", string:rcvRes );
    if( ver[1] != NULL ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/cutenews", value:tmp_version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cutephp:cutenews:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:cutephp:cutenews';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"CuteNews",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
