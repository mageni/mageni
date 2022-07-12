# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117453");
  script_version("2021-05-25T13:52:45+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-25 12:11:37 +0000 (Tue, 25 May 2021)");
  script_name("Jenkins Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_jenkins_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Jenkins automation server is using known default
  credentials for the web login.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"insight", value:"The remote Jenkins automation server is lacking a proper
  password configuration, which makes critical information and actions accessible for people with
  knowledge of the default credentials.

  Note: New Jenkins versions are creating / enforcing a strong and random password. But some
  specific deployments might still use known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the default password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

# nb: Tested against versions:
# 1.651.2
# 2.294

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

from_url = dir;

if( dir == "/" )
  dir = "";

creds = make_list(
  # nb: From:
  # https://docs.openshift.com/container-platform/3.3/using_images/other_images/jenkins.html#initializing-jenkins
  # https://docs.openshift.com/container-platform/4.7/openshift_images/using_images/images-other-jenkins.html#images-other-jenkins-auth_images-other-jenkins
  "admin:password",
  # nb: A few additional default ones
  "admin:admin",
  "admin:jenkins",
  "jenkins:jenkins" );

login_url = dir + "/login";
res = http_get_cache( port:port, item:login_url );
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

report = 'It was possible to login with the following known default credentials (username:password):\n';

urls = make_list(
  # nb: Seems to be only available in newer Jenkins versions
  dir + "/j_spring_security_check",
  dir + "/j_acegi_security_check" );

foreach cred( creds ) {

  split = split( cred, sep:":", keep:FALSE );
  if( max_index( split ) != 2 )
    continue;

  username = split[0];
  password = split[1];

  foreach url( urls ) {

    # We're grabbing a fresh session ID for each try.
    req = http_get( port:port, item:login_url );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    # e.g.
    # Set-Cookie: JSESSIONID.795db1a3=1pukb8ox7in707yredkdal1qj;Path=/;HttpOnly
    # Set-Cookie: JSESSIONID.acb18707=node0vqnaroo8feqo1p6swokjcme7q20.node0; Path=/; HttpOnly
    # nb: Don't include the "." (dot) in the pattern below as login will fail if it is included...
    sessionid = http_get_cookie_from_header( buf:res, pattern:"(JSESSIONID\.[^=]+=[a-z0-9]+)" );
    if( ! sessionid )
      continue;

    headers = make_array( "Content-Type", "application/x-www-form-urlencoded",
                          "Cookie", sessionid );

    if( "/j_spring_security_check" >< url )
      post_data = "j_username=" + username + "&j_password=" + password + "&from=" + urlencode( str:from_url ) + "&Submit=Sign+in";
    else
      post_data = "j_username=" + username + "&j_password=" + password + "&from=" + urlencode( str:from_url ) + "&Submit=log+in";

    req = http_post_put_req( port:port, url:url, data:post_data, add_headers:headers );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res || res !~ "^HTTP/1\.[01] 302" )
      continue;

    # We're getting a new session after the successful login
    sessionid = http_get_cookie_from_header( buf:res, pattern:"(JSESSIONID\.[^=]+=[a-z0-9]+)" );
    if( ! sessionid )
      continue;

    req = http_get_req( port:port, item:from_url, add_headers:make_array( "Cookie", sessionid ) );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    if( "<title>Dashboard [Jenkins]</title>" >< res && '<a href="/logout">' >< res ) {
      VULN = TRUE;
      report += '\n' + username + ":" + password;
      break; # nb: Only report a valid login for one of both URLs...
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );