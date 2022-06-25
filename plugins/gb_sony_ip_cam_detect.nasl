###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sony_ip_cam_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sony IPELA Engine IP Cameras Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107105");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-09 12:56:26 +0100 (Fri, 09 Dec 2016)");
  script_name("Sony IPELA Engine IP Cameras Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Sony IPELA Engine IP Cameras");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
buf = http_get_cache( port:port, item:"/" );
if ( "Sony Network Camera" >!< buf && "SONY Network Camera" >!< buf ) exit( 0 );
camVer = eregmatch( pattern:"[SONY|Sony] Network Camera SNC-([A-Z]+[0-9]+)", string:buf );
if ( camVer[1] ) {
    Ver = "SNC-" + camVer[1];
} else {
    Ver = "Unknown";
}
set_kb_item( name:"sony/ip_camera/model", value:Ver );
cpe = 'cpe:/h:sony:sony_network_camera_snc';

firmVer = eregmatch( pattern:"Server: gen[5|6]th/([0-9.]+)", string:buf );

if ( firmVer[1] ) {
    set_kb_item( name:"sony/ip_camera/firmware", value:firmVer[1] );
    cpe += ':' + firmVer[1];
} else {
     set_kb_item( name:"sony/ip_camera/firmware", value:"Unknown" );
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );
set_kb_item( name:"sony/ip_camera/installed", value:TRUE );

report = build_detection_report( app:'Sony IP Camera', version:firmVer[1], install:"/", cpe:cpe, extra: "Model: " + Ver );
log_message( port:port, data:report );

exit( 0 );

