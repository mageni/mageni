##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_asset_manager_detect.nasl 11407 2018-09-15 11:02:05Z cfischer $
#
# McAfee Asset Manager Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804421");
  script_version("$Revision: 11407 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:02:05 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-17 11:22:05 +0530 (Thu, 17 Apr 2014)");
  script_name("McAfee Asset Manager Version Detection");

  script_tag(name:"summary", value:"Detection of McAfee Asset Manager.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

mamPort = get_http_port( default:443 );
mamRes = http_get_cache( item:"/login", port:mamPort );

if( ">McAfee Asset Manager" >!< mamRes ) exit( 0 );

mamVer = eregmatch( pattern:'">Version ([0-9.]+)', string:mamRes );
if( mamVer[1] ) {
  set_kb_item( name:"www/" + mamPort + "/McAfee/Asset/Manager", value:mamVer[1] );
}

set_kb_item( name:"McAfee/Asset/Manager/installed", value:TRUE );

cpe = build_cpe( value:mamVer[1], exp:"^([0-9.]+)", base:"cpe:/a:mcafee:asset_manager:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:mcafee:asset_manager';

register_product( cpe:cpe, location:mamPort + '/tcp', port:mamPort );

log_message( data: build_detection_report(app:"McAfee Asset Manager",
                                         version:mamVer[1],
                                         install:mamPort + '/tcp',
                                         cpe:cpe,
                                         concluded: mamVer[0] ),
                                         port:mamPort );

exit( 0 );