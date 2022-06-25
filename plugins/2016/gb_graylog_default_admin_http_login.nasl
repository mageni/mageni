###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graylog_default_admin_http_login.nasl 11026 2018-08-17 08:52:26Z cfischer $
#
# Graylog Default HTTP Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:torch_gmbh:graylog2';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105756");
  script_version("$Revision: 11026 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Graylog Default Admin HTTP Login");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Try to login with default credentials admin:admin");
  script_tag(name:"solution", value:"Change the password");
  script_tag(name:"summary", value:"The remote Graylog installation has default credentials set.");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:52:26 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 13:18:59 +0200 (Fri, 10 Jun 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_graylog_web_rest_api_detect.nasl");
  script_require_ports("Services/www", 12900);
  script_mandatory_keys("graylog/rest/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"rest_api" ) ) exit( 0 );

user = "admin";
pass = "admin";
host = get_host_name();

data = '{"username":"' + user + '","password":"' + pass + '","host":"' + host + '"}';

req = http_post_req( port:port, url:"/system/sessions", data:data, accept_header:'application/json', add_headers: make_array( "Content-Type", "application/json","Origin","http://" + host ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 200" && '{"valid_until"' >< buf && '"session_id":' >< buf )
{
  report = 'It was possible to login using username "admin" and password "admin"';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

