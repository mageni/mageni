# OpenVAS Vulnerability Test
# $Id: www_too_long_header10.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: HTTP 1.0 header overflow
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

# I don't even know if it crashes any web server...
# Cf. RFC 1945
# Other references:
# From: "at4r" <at4r@hotmail.com>
# Subject: IIS Vulnerability Content-Type overflow
# To: <vuln-dev@securityfocus.com>
# Date: Mon, 2 Dec 2002 23:31:27 +0100
# Reply-To: "at4r" <at4r@3wdesign.es>
#
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# Subject: Multiple pServ Remote Buffer Overflow Vulnerabilities
# To: "BugTraq" <bugtraq@securityfocus.com>
# Date: Sun, 1 Dec 2002 12:15:52 -0600

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11127");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("HTTP 1.0 header overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
# All the www_too_long_*.nasl scripts were first declared as
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before OpenVAS
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.

  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending an invalid request with a too long header
  (From, If-Modified-Since, Referer or Content-Type)

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbitrary code on your system.");
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

#
r1 = http_get(item:"/", port:port);
r1 = r1 - string("\r\n\r\n");
r1 = r1 + string("\r\n");
#
r = string(r1, "From: ", crap(1024), "@", crap(1024), ".org\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ",
	crap(data: "GMT", length: 1024), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Referer: http://", crap(4096), "/\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Referer: http://", get_host_name(), "/", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Content-Length: ", crap(4096, data: "123456789"), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#
soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

# Note that the message on VULN-DEV did not say that it was possible to
# *crash* IIS. I put it here just in case...

r = string(r1, "Content-Type: application/x-www-form-urlencoded\r\n",
	"Content-Length: 56\r\n",
	# Yes, Content-Type appears twice!
	"Accept-Language: en",
	"Content-Type:", crap(32769), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

#

if (http_is_dead(port: port)) {  security_message(port); exit(0); }
