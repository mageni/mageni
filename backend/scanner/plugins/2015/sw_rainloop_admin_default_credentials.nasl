###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_rainloop_admin_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# RainLoop Webmail admin default credentials
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:rainloop:rainloop';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111011");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RainLoop Webmail admin default credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-30 15:30:00 +0200 (Mon, 30 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("sw_rainloop_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("rainloop/installed");

  script_tag(name:"summary", value:'The remote Rainloop Webmail web interface is prone to a default account
 authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
 access to sensitive information.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: admin/12345');
  script_tag(name:"solution", value:'Change the password.');

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

url = dir + "/?/AdminAppData";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( '"Token":"' >< res) {

  cookie = eregmatch( pattern:"rltoken=([0-9a-z]+);", string:res );
  if( isnull( cookie[1] ) ) exit( 0 );

  xtoken = eregmatch( pattern:'"Token":"([0-9a-z]+)"', string:res );
  if( isnull( xtoken[1] ) ) exit( 0 );

  host = http_host_name( port:port );
  useragent = http_get_user_agent();
  data = string( "Login=admin&Password=12345&Action=AdminLogin&XToken="+xtoken[1] );
  len = strlen( data );

  req = 'POST ' + dir + '/?/Ajax/&q[]=/0/ HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
      	'Cookie: rltoken=' + cookie[1] + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  res = http_keepalive_send_recv( port:port, data:req );

  if( '{"Action":"AdminLogin","Result":true' >< res )
  {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
