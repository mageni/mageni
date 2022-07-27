###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_enterprise_monitor_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# MySQL Enterprise Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140128");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-27 09:22:48 +0100 (Fri, 27 Jan 2017)");
  script_name("MySQL Enterprise Monitor Detection");

  script_tag(name:"summary", value:"This script performs detection of the MySQL Enterprise Monitor Webinterface.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");

port = get_http_port( default:18443 );

url = '/Auth.action';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Log In : MySQL Enterprise Dashboard</title>" >< buf )
{
  CPE = 'cpe:/a:mysql:enterprise_monitor';

  register_product( cpe:CPE, location:"/", port:port, service:"www" );

  report = build_detection_report( app:"MySQL Enterprise Monitor", install:"/", cpe:CPE );
  log_message( port:port, data:report );

  exit( 0 );
}

exit( 0 );

