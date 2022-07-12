###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Default Accounts
#
# Authors:
# Orlando Padilla <orlando.padilla@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11204");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Apache Tomcat Default Accounts");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"solution", value:"Change the default passwords by editing the
  admin-users.xml file located in the /conf/users
  subdirectory of the Tomcat installation.");

  script_tag(name:"summary", value:"This host appears to be the running the Apache Tomcat
  Servlet engine with the default accounts still configured.");

  script_tag(name:"impact", value:"A potential intruder could reconfigure this service in a way
  that grants system access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

#list of default acnts base64()'d
auth[0] = string( "YWRtaW46Y2hhbmdldGhpcw==\r\n\r\n" );	real_auth[0] = string( "admin:tomcat" );
auth[1] = string( "YWRtaW46dG9tY2F0Cg==\r\n\r\n" );	real_auth[1] = string( "admin:admin" );
auth[2] = string( "YWRtaW46YWRtaW4K\r\n\r\n" );		real_auth[2] = string( "tomcat:tomcat" );
auth[3] = string( "dG9tY2F0OnRvbWNhdAo=\r\n\r\n" );	real_auth[3] = string( "admin:tomcat" );
auth[4] = string( "cm9vdDpyb290Cg==\r\n\r\n" );		real_auth[4] = string( "root:root" );
auth[5] = string( "cm9sZTE6cm9sZTEK\r\n\r\n" );		real_auth[5] = string( "role1:role1" );
auth[6] = string( "cm9sZTpjaGFuZ2V0aGlzCg==\r\n\r\n" );	real_auth[6] = string( "role:changethis" );
auth[7] = string( "cm9vdDpjaGFuZ2V0aGlzCg==\r\n\r\n" );	real_auth[7] = string( "root:changethis" );
auth[8] = string( "dG9tY2F0OmNoYW5nZXRoaXMK\r\n\r\n" );	real_auth[8] = string( "tomcat:changethis" );
auth[9] = string( "eGFtcHA6eGFtcHA=\r\n\r\n" );		real_auth[9] = string( "xampp:xampp" );

url = "/admin/contextAdmin/contextList.jsp";

#basereq string
basereq = http_get( item:url, port:port );
basereq = basereq - string( "\r\n\r\n" );

authBasic = string( "Authorization: Basic " );

i = 0;
found = 0;
report = string("");

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! ereg( pattern:"^HTTP/1\.[0-1] 401 ", string:buf ) )exit( 0 );
if( ( "<title>Context list</title>" >< buf ) || ( "<title>Context Admin</title>" >< buf ) ) exit( 0 );

while( auth[i] ) {

  t0 = basereq;
  t1 = authBasic;
  t1 = string( t1, auth[i] );
  t0 = string( t0, t1 );

  buf = http_keepalive_send_recv( port:port, data:t0, bodyonly:FALSE );

  # minor changes between versions of jakarta
  if( ( "<title>Context list</title>" >< buf ) || ("<title>Context Admin</title>" >< buf ) ) {
    found++;
    if( found == 1 ) {
      accounts = string( "The following accounts were discovered: \n", real_auth[i], "\n" );
    } else {
      accounts = string( accounts, string( real_auth[i], "\n" ) );
    }
  }
  i++;
}

# should we include the plugin description?
if( found ) {
  report = report_vuln_url( port:port, url:url );
  report += '\n\n' + accounts;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );