###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Adobe Flash Media Server Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800559");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Adobe Flash Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8086);
  script_mandatory_keys("FlashCom/banner");

  script_tag(name:"summary", value:"This script detects the version of Adobe Flash Media Server and
  sets the result in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8086 );
banner = get_http_banner( port:port );

if( "erver: FlashCom" >!< banner ) exit( 0 );

version = "unknown";

vers = eregmatch( pattern:"FlashCom/([0-9.]+)", string:banner );

if( ! isnull( vers ) ) version = vers[1];

set_kb_item( name:"www/" + port + "/Adobe/FMS", value:version );
set_kb_item( name:"Adobe/FMS/installed", value:TRUE );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_media_server:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:adobe:flash_media_server';

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data:build_detection_report( app:"Adobe Flash Media Server",
                                          version:version,
                                          install:port + '/tcp',
                                          cpe:cpe,
                                          concluded:vers[0] ),
                                          port:port );

exit( 0 );
