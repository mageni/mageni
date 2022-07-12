###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apache_axis2_admin_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Axis2 axis2-admin default credentials
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

CPE = 'cpe:/a:apache:axis2';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111006");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(44055);
  script_cve_id("CVE-2010-0219");
  script_name("Apache Axis2 axis2-admin default credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-18 08:00:00 +0100 (Wed, 18 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_detect.nasl");
  script_require_ports("Services/www", 8080, 8081);
  script_mandatory_keys("axis2/installed");

  script_tag(name:"summary", value:'The remote Apache Axi2 web interface is prone to a default account
 authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
 access to sensitive information, modify system configuration or execute code by uploading
 malicious webservices.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: admin/axis2');
  script_tag(name:"solution", value:'Change the password.');

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44055");
  script_xref(name:"URL", value:"http://ws.apache.org/axis2/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15869");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = http_host_name(port:port);
useragent = http_get_user_agent();

data = string( "userName=admin&password=axis2&submit=+Login+" );
len = strlen( data );

req = 'POST ' + dir + '/axis2-admin/login HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;

res = http_keepalive_send_recv( port:port, data:req );

if( "Welcome to Axis2 Web Admin Module !!" >< res )
{
  security_message( port:port );
  exit( 0 );
}

#Old location for Axis2 0.9.3 and below
url = string( dir, "/adminlogin?userName=admin&password=axis2&submit=+Login++" );
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:res );
if( isnull( cookie[1] ) ) exit( 0 );

req = 'GET ' + dir + '/admin.jsp HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
      '\r\n';

res = http_keepalive_send_recv( port:port, data:req );

if( "Welcome to the Axis2 administration system!" >< res )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
