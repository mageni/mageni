###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_glassfish_admin_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Oracle GlassFish Admin Default Credentials
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

CPE = "cpe:/a:oracle:glassfish_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111073");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-17 15:00:00 +0100 (Thu, 17 Dec 2015)");
  script_name("Oracle GlassFish Admin Default Credentials");

  script_tag(name:"summary", value:'The remote Oracle GlassFish is prone to a default
 account authentication bypass vulnerability.');
  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
 access to sensitive information.');
  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials "admin:admin"
 or "admin:"');
  script_tag(name:"solution", value:'Change the password.');

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("GlassFish_detect.nasl");
  script_require_ports("Services/www", 4848);
  script_mandatory_keys("GlassFish/installed");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_kb_item( "www/" + port + "/GlassFishAdminConsole" ) ) exit( 0 );

res = http_get_cache( item:"/", port:port );

cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:res );
if( isnull( cookie[1] ) ) exit( 0 );

credentials = make_list( "admin:admin","admin:none" );

host = http_host_name( port:port );
useragent = http_get_user_agent();

foreach credential( credentials ) {

  user_pass = split( credential, sep:":", keep:FALSE );

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  if( tolower( pass ) == "none" ) pass = "";

  data = string( "j_username=" + user + "&j_password=" + pass + "&loginButton=Login&loginButton.DisabledHiddenField=true" );
  len = strlen( data );

  req = 'POST /j_security_check HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Referer: http://' + host + '/\r\n' +
        'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
        'Connection: keep-alive\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req );

  if( ( res =~ "HTTP/1.. 302 Moved Temporarily" || res =~ "HTTP/1.. 302 Found" ) && '/">here' >< res ) {

    cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:res );
    if( isnull( cookie[1] ) ) exit( 0 );

    req = 'GET / HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
          'Connection: keep-alive\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    req = 'GET /common/index.jsf HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/\r\n' +
          'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
          'Connection: keep-alive\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "<title>Common Tasks</title>" >< res || "Log Out of GlassFish Administration Console" >< res ||
        "<title>GlassFish Console - Common Tasks</title>" >< res ) {
       report = report_vuln_url( port:port, url:"/common/index.jsf" );
       report = report + '\n\nIt was possible to login using the following credentials:\n\n' + user + ':' + pass + '\n';

       security_message( port:port, data:report );
       exit( 0 );
    }
  }
}

exit( 99 );
