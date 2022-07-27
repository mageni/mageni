###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_ms_lync_server_remote_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Microsoft Lync Server Remote Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111035");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-09-03 16:00:00 +0200 (Thu, 03 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Microsoft Lync Server Remote Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("RTC/banner");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to identify Microsoft Lync Server.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port( default:443 );
banner = get_http_banner( port:port );

if( concluded = eregmatch( string: banner, pattern: "Server: RTC/(5.0|6.0)" ) ) {

cpe = 'cpe:/a:microsoft:lync';

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data: build_detection_report( app:"Microsoft Lync Server",
                                               install:port + '/tcp',
                                               cpe:cpe,
                                               concluded: concluded[0]),
                                               port:port);

}

exit(0);
