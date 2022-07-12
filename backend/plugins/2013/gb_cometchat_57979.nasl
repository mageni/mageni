###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cometchat_57979.nasl 11399 2018-09-15 07:45:12Z cfischer $
#
# CometChat Remote Code Execution and Cross-Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103669");
  script_bugtraq_id(57979);
  script_version("$Revision: 11399 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("CometChat Remote Code Execution and Cross-Site Scripting Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 09:45:12 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-02-26 12:54:40 +0100 (Tue, 26 Feb 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57979");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"summary", value:"CometChat is prone to a cross-site scripting vulnerability and a
  remote code-execution vulnerability because the application fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and launch other attacks.

  An attacker can exploit the remote code-execution issue to execute arbitrary code in the context of the
  application. Failed attacks may cause denial-of-service conditions.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cometchat", "/chat", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/index.html';
  buf = http_get_cache( item:url, port:port );

  if( "<title>CometChat" >< buf ) {
    url = dir + '/modules/chatrooms/chatrooms.php?action=phpinfo';
    if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
