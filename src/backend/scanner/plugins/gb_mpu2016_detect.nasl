###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mpu2016_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Emerson Network Power Avocent MergePoint Unity 2016 KVM Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103893");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-01-27 18:43:12 +0100 (Mon, 27 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Emerson Network Power Avocent MergePoint Unity 2016 KVM Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:443 );

buf = http_get_cache( item:"/login.php", port:port );

if( "<title>MPU2016 Explorer" >!< buf ) exit( 0 );

vers = "unknown";
install = "/";

version = eregmatch ( pattern:"Appliance firmware version ([0-9.]+)", string:buf );
if( ! isnull( version[1] ) ) vers = version[1];

set_kb_item( name:"MPU2016/installed", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware:" );
if( isnull( cpe ) )
  cpe = "cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware";

register_product( cpe:cpe, location:install, port:port, service:"www" );

log_message( data:build_detection_report( app:"Emerson Network Power Avocent MergePoint Unity 2016 KVM",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );

exit( 0 );
