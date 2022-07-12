###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharp_mx_m850_default_administrator_password.nasl 10322 2018-06-26 06:37:28Z cfischer $
#
# Sharp MX-M850 Default Administrator Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103667");
  script_version("$Revision: 10322 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sharp MX-M850 Default Administrator Password");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 08:37:28 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 12:01:48 +0100 (Fri, 22 Feb 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Rapid_Logic/banner");

  script_xref(name:"URL", value:"http://sharp-world.com/");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote Sharp MX-M850 has the default password 'admin'.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if("Server: Rapid Logic/1.1" >!< banner) exit(0);

url = '/login.html';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req);

if("Set-Cookie" >!< buf) exit(0);
cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:buf);
if(isnull(cookie[1])) exit(0);

host = http_host_name(port:port);

req = string("POST /login.html?/main.html HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "DNT: 1\r\n",
             "Connection: close\r\n",
             "Referer: http://",host,"/login.html?/main.html\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Cookie: ",cookie[1],"\r\n",
             "Content-Length: 68\r\n",
             "\r\n",
             "ggt_textbox%2810006%29=admin&action=loginbtn&ggt_hidden%2810008%29=3");
res = http_send_recv(port:port, data:req);

if("Set-Cookie" >!< res) exit(0);
cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:res);
if(isnull(cookie[1])) exit(0);

req = string("GET /security_password.html HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Cookie: ", cookie[1],"\r\n\r\n");
res = http_send_recv(port:port, data:req);

if("User Name: Administrator" >< res && "Logout(L)" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
