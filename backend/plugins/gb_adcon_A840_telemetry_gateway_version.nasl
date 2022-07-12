###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adcon_A840_telemetry_gateway_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Adcon A840 Telemetry Gateway Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105490");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-17 16:20:27 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Detection");

  script_tag(name:"summary", value:"This Script get the via HTTP or Telnet detected Adcon A840 Telemetry Gateway version");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_adcon_A840_telemetry_gateway_http_detect.nasl", "gb_adcon_A840_telemetry_gateway_telnet_detect.nasl");
  script_mandatory_keys("tg_A840/installed");
  exit(0);
}

include("host_details.inc");

cpe = 'cpe:/a:adcon:telemetry_gateway_a840';
source = 'telnet';
vers = 'unknown';

if( ! version = get_kb_item( "tg_A840/telnet/version" ) )
{
  source = 'HTTP';
  version = get_kb_item( "tg_A840/http/version" );
}

if( version )
{
  vers = version;
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:source );

log_message( data: build_detection_report( app:"Adcon A840 Telemetry Gateway",
                                           version:vers,
                                           install:source,
                                           cpe:cpe,
                                           concluded: source ),
             port:0 );


exit(0);

