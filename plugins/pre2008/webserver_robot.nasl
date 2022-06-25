###############################################################################
# OpenVAS Vulnerability Test
# $Id: webserver_robot.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# robot(s).txt exists on the Web Server
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10302");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("robot(s).txt exists on the Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Any serious web search engine will honor the /robot(s).txt file
  and not scan the files and directories listed there.

  Any entries listed in this file are not even hidden anymore.");

  script_tag(name:"summary", value:"Web Servers can use a file called /robot(s).txt to ask search engines
  to ignore certain files and directories. By nature this file can not be used to protect private files
  from public read access.");

  script_tag(name:"solution", value:"Review the content of the robots file and consider removing the files
  from the server or protect them in other ways in case you actually intended non-public availability.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host))exit(0);

res = is_cgi_installed_ka(port:port, item:"/robot.txt");
if(res) {
  sockwww = http_open_socket(port);
  if(!sockwww) exit(0);

  sendata = http_get(item:"/robot.txt", port:port);
  send(socket:sockwww, data:sendata);
  headers = http_recv_headers2(socket:sockwww);
  body = http_recv_body(socket:sockwww, headers:headers, length:0);
  http_close_socket(sockwww);
  if("llow" >< body || "agent:" >< body){
    body = string("The file 'robot.txt' contains the following:\n", body);
    log_message(port:port, data:body);
  }
} else {
  res = is_cgi_installed_ka(port:port, item:"/robots.txt");
  if(!res) exit(0);
  sockwww = http_open_socket(port);
  if(!sockwww) exit(0);

  sendata = http_get(item:"/robots.txt", port:port);
  send(socket:sockwww, data:sendata);
  headers = http_recv_headers2(socket:sockwww);
  body = http_recv_body(socket:sockwww, headers:headers, length:0);
  http_close_socket(sockwww);
  if("llow" >!< body && "agent:" >!< body) exit(0);
  body = string("The file 'robots.txt' contains the following:\n", body);
  log_message(port:port, data:body);
}

exit(0);