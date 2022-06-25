###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rabbitmq_web_management_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# RabbitMQ Web Management Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105178");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-22 17:22:26 +0100 (Thu, 22 Jan 2015)");
  script_name("RabbitMQ Web Management Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to detect the RabbitMQ webmanagement interface from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 15672);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:15672 );

url = "/";
buf = http_get_cache( item:url, port:port );

if( "<title>RabbitMQ Management</title>" >!< buf ) exit( 0 );

cpe = 'cpe:/a:pivotal_software:rabbitmq';
register_product( cpe:cpe, location:url, port:port, service:"www" );

set_kb_item( name:"rabbitmq/installed", value:TRUE );
set_kb_item( name:"rabbitmq/web/installed", value:TRUE );

log_message( port:port, data:'RabbitMQ Management Interface is running at this port.\nUrl: ' + url + '\nCPE: ' + cpe + '\n' );
exit(0);

