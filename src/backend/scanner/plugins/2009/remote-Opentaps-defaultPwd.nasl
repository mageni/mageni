###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-Opentaps-defaultPwd.nasl 9946 2018-05-24 10:25:05Z cfischer $
#
# Opentaps ERP + CRM Default Credentials
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:opentaps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101024");
  script_version("$Revision: 9946 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-24 12:25:05 +0200 (Thu, 24 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-25 22:17:58 +0200 (Sat, 25 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Opentaps ERP + CRM Default Credentials");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Web application abuses");
  script_dependencies("remote-detect-Opentaps_ERP_CRM.nasl");
  script_mandatory_keys("OpentapsERP/installed");

  script_tag(name:"summary", value:"The remote host is running Opentaps ERP + CRM with default
  credentials.");

  script_tag(name:"solution", value:"Set a strong password for the mentioned accounts.");

  script_tag(name:"impact", value:"This allow an attacker to gain possible administrative access to
  the remote application.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit(0);
if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) ) exit( 0 ); # To have a reference to the Detection-NVT

modules = get_kb_list( "OpentapsERP/" + port + "/modules" );
if( modules ) {

  # http://www.opentaps.org/docs/index.php/General_Installation_of_Opentaps#Signing_In
  credentials = make_array( "1", "1",
                            "2", "2",
                            "admin", "ofbiz",
                            "DemoCustomer", "ofbiz" );

  foreach username( keys( credentials ) ) {

    postdata = string( "USERNAME=" + username + "&PASSWORD=" + credentials[username] );
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
      # <h2>Welcome <br />THE ADMINISTRATOR</h2>
      # <h2>Welcome <br />Limited Administrator</h2>
      # <h2>Welcome <br />Demo Customer</h2>
      welcomeMsg = egrep( pattern:'(Welcome(&nbsp;| | <br />)(THE(&nbsp;| )ADMIN|Limited Administrator|Demo Customer)|THE PRIVILEGED ADMINISTRATOR|/control/logout">Logout</a></li>)', string:res );
      if( ! welcomeMsg ) continue;
      VULN = TRUE;
      report += username + ":" + credentials[username] + ":" + report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
    }
  }

  if( VULN ) {
    report = 'It was possible to login with default credentials at the following modules (username:password:url):\n\n' + report;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
