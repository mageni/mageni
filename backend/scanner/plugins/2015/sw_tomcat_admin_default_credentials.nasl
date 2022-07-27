###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Server Administration Unauthorized Access Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111013");
  script_version("2019-05-10T11:41:35+0000");
  script_name("Apache Tomcat Server Administration Unauthorized Access Vulnerability");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2015-04-10 15:00:00 +0200 (Fri, 10 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"solution", value:"Change or remove the user from tomcat-users.xml.");

  script_tag(name:"summary", value:"Apache Tomcat Server Administration is prone to a remote
  unauthorized-access vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

req = http_get( item:"/admin/", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie = eregmatch( pattern:"JSESSIONID=([0-9A-Z]+);", string:res );
if( isnull( cookie[1] ) ) exit( 0 );

if( "Tomcat Server Administration" >< res ) {

  vuln = FALSE;
  report = "";

  credentials = make_list( "tomcat:tomcat", "tomcat:none", "ADMIN:ADMIN", "admin:admin", "manager:manager", "admin:password", "ovwebusr:OvW*busr1", "j2deployer:j2deployer", "tomcat:s3cret", "cxsdk:kdsxc", "xampp:xampp", "QCC:QLogic66", "root:owaspbwa", "role1:tomcat", "both:tomcat", "root:changethis", "admin:changethis" );

  host = http_host_name( port:port );
  useragent = http_get_user_agent();
  foreach credential( credentials ) {

    user_pass = split( credential, sep:":", keep:FALSE );

    user = chomp( user_pass[0] );
    pass = chomp( user_pass[1] );

    if( tolower( pass ) == "none" ) pass = "";

    data = string( "j_username=" + user + "&j_password=" + pass );
    len = strlen( data );

    req = 'POST /admin/j_security_check;jsessionid=' + cookie[1] + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/admin/\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
          'Connection: keep-alive\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          data;
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res =~ "HTTP/1.. 302" && "/admin/" >< res ) {

      req = 'GET /admin/ HTTP/1.1\r\n' +
            'Host: ' + host + '\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
            'Accept-Language: en-US,en;q=0.5\r\n' +
            'Referer: http://' + host + '/admin/\r\n' +
            'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
            'Connection: keep-alive\r\n' +
            '\r\n';
      res = http_keepalive_send_recv( port:port, data:req );

      req = 'GET /admin/banner.jsp HTTP/1.1\r\n' +
            'Host: ' + host + '\r\n' +
            'User-Agent: ' + useragent + '\r\n' +
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
            'Accept-Language: en-US,en;q=0.5\r\n' +
            'Referer: http://' + host + '/admin/\r\n' +
            'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
            'Connection: keep-alive\r\n' +
            '\r\n';
      res = http_keepalive_send_recv( port:port, data:req );

      if( "/admin/commitChanges.do" >< res ) {
         report += "It was possible to login into the Tomcat Server Administration at " + report_vuln_url( port:port, url:"/admin/index.jsp", url_only:TRUE ) + ' using user "' + user + '" with password "' + pass + '"';
         vuln = TRUE;
      }
    }
  }

  if( vuln ) {
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
