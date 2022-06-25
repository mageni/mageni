###############################################################################
# OpenVAS Vulnerability Test
# $Id: roxen_counter.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Roxen counter module
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
# Minor changes by rd :
# - check for the error code in the first line only
# - compatible with no404.nasl
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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
  script_oid("1.3.6.1.4.1.25623.1.0.10207");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Roxen counter module");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Roxen/banner");

  script_tag(name:"solution", value:"Disable the counter-module. There might be a patch available in the future.");

  script_tag(name:"summary", value:"The Roxen Challenger webserver is running and the counter module is installed.

  Requesting large counter GIFs eats up CPU-time on the server. If the server does not support threads this will
  prevent the server from serving other clients.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);

banner = get_http_banner(port:port);
if ( ! banner || "Roxen" >!< banner )
  exit(0);

if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

no404 = http_get_no404_string(port:port, host:host);
no404 = tolower(no404);

url = string("/counter/1/n/n/0/3/5/0/a/123.gif");
data = http_get(item:url, port:port);
soc = http_open_socket(port);
if(!soc) exit(0);

send(socket:soc, data:data);
line = recv_line(socket:soc, length:1024);
buf = http_recv(socket:soc);
buf = tolower(buf);
must_see = "image";
http_close_socket(soc);

if(no404 && no404 >< buf) exit(0);

if((" 200 " >< line) && (must_see >< buf)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);