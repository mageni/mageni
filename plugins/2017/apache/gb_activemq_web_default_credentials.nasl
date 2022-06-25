###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_activemq_web_default_credentials.nasl 10726 2018-08-02 07:46:22Z cfischer $
#
# Apache ActiveMQ Web Console Default / No Credentials
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108253");
  script_version("$Revision: 10726 $");
  script_name("Apache ActiveMQ Web Console Default / No Credentials");
  script_tag(name:"last_modification", value:"$Date: 2018-08-02 09:46:22 +0200 (Thu, 02 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-13 10:31:0 +0200 (Fri, 13 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_apache_activemq_detect.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("ActiveMQ/Web/auth_or_unprotected");

  script_xref(name:"URL", value:"https://activemq.apache.org/web-console.html");

  script_tag(name:"summary", value:"The Apache ActiveMQ Web Console is unprotected or prone
  to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information.");

  script_tag(name:"solution", value:"Change or set the password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection-NVT

vuln = FALSE;
report = "It was possible to access the Apache ActiveMQ Web Console at:";

host = http_host_name( dont_add_port:TRUE );

# nb: Set by gb_apache_activemq_detect.nasl
unprotectedUrls = get_kb_list( "www/" + host + "/" + port + "/ActiveMQ/Web/unprotected" );
authRequireUrls = get_kb_list( "www/" + host + "/" + port + "/ActiveMQ/Web/auth_required" );

if( ! isnull( unprotectedUrls) ) {

  # Sort to not report changes on delta reports if just the order is different
  unprotectedUrls = sort( unprotectedUrls );

  foreach url( unprotectedUrls ) {
    report += '\n\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + ' without any username/password';
    vuln = TRUE;
  }
}

if( ! isnull( authRequireUrls ) ) {

  # https://activemq.apache.org/web-console.html
  credentials = make_list( "admin:admin", "user:user" );

  # Sort to not report changes on delta reports if just the order is different
  authRequireUrls = sort( authRequireUrls );

  foreach url( authRequireUrls ) {

    foreach credential( credentials ) {

      user_pass = split( credential, sep:":", keep:FALSE );

      user = chomp( user_pass[0] );
      pass = chomp( user_pass[1] );

      userpass = string( user, ":", pass );
      userpass64 = base64( str:userpass );

      req = http_get_req( port:port, url:url, add_headers:make_array( "Authorization", "Basic " + userpass64 ) );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( res =~ "HTTP/1\.[01] 200" && egrep( pattern:"(Apache )?ActiveMQ( Console)?</title>", string:res, icase:TRUE ) ) {
        report += '\n\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + ' using user "' + user + '" with password "' + pass + '"';
        vuln = TRUE;
      }
    }
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
