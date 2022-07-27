###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Manager Remote Unauthorized Access Vulnerability
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103550");
  script_version("2019-05-10T11:41:35+0000");
  script_name("Apache Tomcat Manager Remote Unauthorized Access Vulnerability");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2012-08-22 17:19:15 +0200 (Wed, 22 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected", "ApacheTomcat/auth_required");

  script_tag(name:"solution", value:"Change or remove the user from tomcat-users.xml.");

  script_tag(name:"summary", value:"Apache Tomcat Manager/Host Manager/Server Status is prone to a remote
  unauthorized-access vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to upload and execute arbitrary
  code, which will facilitate a complete compromise of the affected computer.");

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

credentials = make_list( "tomcat:tomcat",
                         "tomcat:none",
                         "ADMIN:ADMIN",
                         "admin:admin",
                         "manager:manager",
                         "admin:password",
                         "ovwebusr:OvW*busr1",
                         "j2deployer:j2deployer",
                         "tomcat:s3cret",
                         "cxsdk:kdsxc",
                         "xampp:xampp",
                         "QCC:QLogic66",
                         "root:owaspbwa",
                         "role1:tomcat",
                         "both:tomcat",
                         "root:changethis",
                         "admin:changethis" );

# nb: This is expected to be here, the port will be added with a later call...
host = http_host_name( dont_add_port:TRUE );

vuln = FALSE;
report = ""; # nb: To make openvas-nasl-lint happy...

# nb: Set by gb_apache_tomcat_consolidation.nasl
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/ApacheTomcat/auth_required" );
if( isnull ( authRequireUrls ) ) exit( 0 );

# Sort to not report changes on delta reports if just the order is different
authRequireUrls = sort( authRequireUrls );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach url( authRequireUrls ) {

  foreach credential( credentials ) {

    user_pass = split( credential, sep:":", keep:FALSE );

    user = chomp( user_pass[0] );
    pass = chomp( user_pass[1] );

    if( tolower( pass ) == "none" ) pass = "";

    userpass = string( user, ":", pass );
    userpass64 = base64( str:userpass );

    req = string( "GET ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Authorization: Basic ", userpass64, "\r\n",
                  "\r\n" );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res =~ "HTTP/1.. 200" && "Tomcat Web Application Manager" >< res || res =~ "HTTP/1.. 200" && "Tomcat Virtual Host Manager" >< res || res =~ "HTTP/1.. 200" && "Server Status" >< res && "Complete Server Status" >< res) {
      report += "Default Tomcat Credentials at " + report_vuln_url( port:port, url:url, url_only:TRUE ) + ' using user "' + user + '" with password "' + pass;
      vuln = TRUE;
    }
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
