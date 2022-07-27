###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_magento_magmi_detect.nasl 10894 2018-08-10 13:09:25Z cfischer $
#
# Magmi database client for Magento Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111042");
  script_version("$Revision: 10894 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-15 12:00:00 +0200 (Thu, 15 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Magmi database client for Magento Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to extract the version from
  the reply.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");


# First see if Magento was already detected
port = get_app_port( cpe:CPE );
if( port  ) {
  magentoDir = get_app_location( cpe:CPE, port:port );
} else {
  port = get_http_port( default:80 );
}

if( ! can_host_php( port:port ) ) exit( 0 );

if( magentoDir ) {
  if( magentoDir == "/" ) magentoDir = "";
  dirs = make_list_unique( cgi_dirs(port:port), "/magmi-importer", "/magmi", magentoDir + "/magmi-importer", magentoDir + "/magmi" );
} else {
  dirs = make_list_unique( cgi_dirs(port:port), "/magmi-importer", "/magmi" );
}

foreach dir ( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/web/magmi.php';
  req = http_get( item: url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  url = dir + '/ReleaseNotes.txt';
  req = http_get( item: url, port:port );
  res2 = http_keepalive_send_recv( port:port, data:req );

  if( '<link rel="stylesheet" href="css/magmi.css"></link>' >< res || "RELEASE NOTES FOR MAGMI" >< res2) {

    version = "unknown";

    ver = eregmatch( pattern:"RELEASE NOTES FOR MAGMI ([0-9a-zA-Z.]+)", string:res2 );

    if( ! isnull( ver[1] ) ) version = ver[1];

    set_kb_item( name:"www/" + port + "/magmi", value:version );
    set_kb_item( name:"magmi/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9a-zA-Z.]+)", base:"cpe:/a:magmi:magmi:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:magmi:magmi';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Magmi",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded: ver[0]),
                                               port:port);
  }
}

exit(0);
