# OpenVAS Vulnerability Test
# $Id: shttp_detect.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: S-HTTP detection
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

# References:
# RFC 2660 The Secure HyperText Transfer Protocol

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11720");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("S-HTTP detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("General");
  script_dependencies("find_service.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"This web server supports S-HTTP, a cryptographic layer
 that was defined in 1999 by RFC 2660.
 S-HTTP has never been widely implemented and you should
 use HTTPS instead.

 As rare or obsolete code is often badly tested, it would be
 safer to use another server or disable this layer somehow.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

#

include("http_func.inc");
port = get_http_port(default:80);
host = http_host_name( port:port );

soc = http_open_socket(port);
if(!soc)exit(0);
req = string("Secure * Secure-HTTP/1.4\r\n",
		"Host: ", host, "\r\n",
		"Connection: close\r\n",
		"\r\n");
send(socket: soc, data: req);
r = recv_line(socket: soc, length: 256);
http_close_socket(soc);
if (ereg(pattern:"Secure-HTTP/[0-9]\.[0-9] 200 ", string:r)) {
  security_message(port:port);
  exit(0);
}

exit(99);