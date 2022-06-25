###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_detect.nasl 10822 2018-08-07 15:31:31Z cfischer $
#
# OCS Inventory NG Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# updated by Madhuri D <dmadhuri@secpod.com> on 2011-11-15
#  - To detect the newer versions
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902058");
  script_version("$Revision: 10822 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 17:31:31 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OCS Inventory NG Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed OCS Inventory NG version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/ocsreports", "/", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes =~ "^HTTP/1\.[01] 200" && "OCS Inventory" >< rcvRes ) {

    set_kb_item( name:"ocs_inventory_ng/detected", value:TRUE );

    version = "unknown";

    ver = eregmatch( pattern:"Ver. (<?.>)?([0-9.]+).?(RC[0-9]+)?", string:rcvRes );
    if( ! isnull( ver[2] ) ) {
      if( ! isnull( ver[3] ) ) {
        version = ver[2] + "." + ver[3];
      } else {
        version = ver[2];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/OCS_Inventory_NG", value:tmp_version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+).?(RC[0-9]+)?", base:"cpe:/a:ocsinventory-ng:ocs_inventory_ng:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ocsinventory-ng:ocs_inventory_ng';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"OCS Inventory NG",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
