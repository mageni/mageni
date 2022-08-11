###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-ApacheOfbiz-defaultPwd.nasl 9893 2018-05-17 15:57:09Z cfischer $
#
# Apache Open For Business (OFBiz) Default Admin Credentials
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:open_for_business_project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101023");
  script_version("$Revision: 9893 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-17 17:57:09 +0200 (Thu, 17 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-25 21:03:34 +0200 (Sat, 25 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache Open For Business (OFBiz) Default Admin Credentials");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Default Accounts");
  script_dependencies("remote-detect-ApacheOfbiz.nasl");
  script_mandatory_keys("ApacheOFBiz/installed");

  script_tag(name:"summary", value:"The remote host is running the Apache OFBiz with default
  administrator username and password.");

  script_tag(name:"solution", value:"Set a strong password for the 'admin' account.");

  script_tag(name:"impact", value:"This allow an attacker to gain administrative access to
  the remote application.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) ) exit( 0 ); # To have a reference to the Detection-NVT

modules = get_kb_list( "ApacheOFBiz/" + port + "/modules" );
if( modules ) {

  postdata = string( "USERNAME=admin&PASSWORD=ofbiz" );
  postlen = strlen( postdata );

  # Sort no not report on changes on delta reports if the order is different
  modules = sort( modules );

  host = http_host_name( port:port );

  foreach module( modules ) {
    url = module + "/control/login";
    req = string( "POST ", url, " HTTP/1.1\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", postlen , "\r\n",
                  "Referer: http://", host, url, "\r\n",
                  "Host: ", host,
                  "\r\n\r\n",
                  postdata );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res ) continue;
    welcomeMsg = egrep( pattern:'(Welcome THE ADMIN|THE PRIVILEGED ADMINISTRATOR|/control/logout">Logout</a></li>)', string:res );
    if( ! welcomeMsg ) continue;
    VULN = TRUE;
    report += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }
  if( VULN ) {
    report = 'It was possible to login with the default credentials "admin:ofbiz" at the following modules:\n\n' + report;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
