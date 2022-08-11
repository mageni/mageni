# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108746");
  script_version("2020-04-16T08:50:48+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 08:04:09 +0000 (Wed, 15 Apr 2020)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_name("Huawei VRP Default Credentials (HTTP)");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("huawei/vrp/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1000178166/1257fc63/what-is-the-default-login-password");

  script_tag(name:"summary", value:"The remote Huawei Versatile Routing Platform (VRP) device is using
  known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The remote Huawei Versatile Routing Platform (VRP) device is lacking
  a proper password configuration, which makes critical information and actions accessible for people
  with knowledge of the default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'admin:admin'
  or 'admin:admin@huawei.com'.");

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
include("dump.inc");

# nb: Tested against:
# S5735-S24T4X with firmware V200R019C00SPC500

CPE_PREFIX = "cpe:/o:huawei:";

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

# nb: Array key is the password as we can't use the "admin" as the key twice...
creds = make_array( "admin@huawei.com", "admin",
                    "admin", "admin" );

url = "/login.cgi";
headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

foreach password( keys( creds ) ) {

  username = creds[password];
  data = "UserName=" + username + "&Password=" + password + "&Edition=0";

  req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res )
    continue;

  # nb: When doing the request on 80/tcp (which is redirecting to 443/tcp) then we're
  # getting a HTTP/1.1 403 Forbidden back so we're breaking out of the loop directly
  # so that we're not unecessarily checking the second credentials.
  if( res =~ "^HTTP/1\.[01] 403" )
    break;

  # For a failed login the ErrorMsg=1008 is thrown but still we're getting a 200 back
  # so we need to check both.
  if( res !~ "^HTTP/1\.[01] 200" || "ErrorMsg=1008" >< res )
    continue;

  sessionid = http_get_cookie_from_header( buf:res, pattern:"(SessionID=[^;]+;)" );
  if( ! sessionid )
    continue;

  body = http_extract_body_from_response( data:res );
  if( ! body )
    continue;

  # The response should look like e.g. for a valid account:
  # NoChangeFlag=0&Location=/simple/view/main/main.html&Token=Pjx6Bpwd0tO6i3ky0OPnDMNIhAlgYKdn
  # and the following if a change of a password was requested (two different possibilities):
  # ChangeFlag=2&Token=iJYPmuHUKwqu0Dj5KiMd3zAZileTD4Bz&AAAMsg=
  # ChangeFlag=1&Token=iJYPmuHUKwqu0Dj5KiMd3zAZileTD4Bz&AAAMsg=
  location = eregmatch( string:body, pattern:"Location=([^&]+)", icase:FALSE );
  if( ! location[1] && ( "ChangeFlag=2" >< body || "ChangeFlag=1" >< body ) )
    url = "/simple/view/main/modifyPwd.html";
  else if( ! location[1] )
    url = "/simple/view/main/main.html"; # Fallback
  else
    url = location[1];

  token = eregmatch( string:body, pattern:"(Token=[^&]+)", icase:FALSE );
  if( ! token[1] )
    continue;

  # Cookie should look like e.g.:
  # Cookie: LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=username; loginFlag=true; SessionID=CLkd5brguZa1xcvRMMxnrvqOijjGaGRl; Token=Pjx6Bpwd0tO6i3ky0OPnDMNIhAlgYKdn
  cookie = "LSWlanguage=lsw_lang_en.js; icbs_language=en; UserName=" + username + "; loginFlag=true; " + sessionid + " " + token[1];
  headers = make_array( "Cookie" , cookie );
  req = http_get_req( port:port, url:url + "?language=en", add_headers:headers );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  if( 'icbs_lang="LG.publicModule.equ_board"' >< res || 'icbs_lang="LG.tree.common_maintenance"' >< res ) {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '"';
  } else if( "'loginCaption' id='oldPasswordCaption'" >< res || "'loginCaption' id='newPasswordCaption'" >< res ) {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '" (The system is enforcing a change of the current password)';
  }
}

if( VULN ) {
  report = 'It was possible to login with the following default credentials:\n' + report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
