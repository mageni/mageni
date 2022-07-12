###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_rest_api_unprotected.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# MongoDB Unauthenticated REST API
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
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105234");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11872 $");

  script_name("MongoDB Unauthenticated REST API");

  script_xref(name:"URL", value:"http://docs.mongodb.org/ecosystem/tools/http-interfaces");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
 may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response");

  script_tag(name:"solution", value:"Disable or restrict access to the MongoDB REST API or the MongoDB HTTP
interface");

  script_tag(name:"summary", value:"The remote MongoDB REST API is unprotected");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-13 09:16:37 +0100 (Fri, 13 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_mongodb_webadmin_detect.nasl");
  script_require_ports("Services/www", 28017);
  script_mandatory_keys("mongodb/webadmin/port");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("mongodb/webadmin/port");
if( ! port ) port = 28017;

if( ! get_port_state( port ) ) exit( 0 );

url = '/local/startup_log/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( eregmatch( pattern:'"total_rows" : [0-9]+ ,', string:buf ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
