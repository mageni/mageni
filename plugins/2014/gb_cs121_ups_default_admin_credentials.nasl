###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cs121_ups_default_admin_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# CS121 UPS Default Admin Credentials
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105023");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CS121 UPS Default Admin Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-05-12 11:02:06 +0200 (Mon, 12 May 2014)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("HyNetOS/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:'The remote CS121 UPS web interface is prone to a default
 account authentication bypass vulnerability.');
  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
 access to sensitive information or modify system configuration.');
  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials.');
  script_tag(name:"solution", value:'Change the password.');

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );

if( "HyNetOS" >!< banner ) exit( 0 );

buf = http_get_cache(item:"/", port:port);

if( "<title>CS121" >!< buf ) exit( 0 );

req = http_get(item:'/admin/net.shtml', port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( "401 Unauthorized" >!< buf ) exit( 0 );

userpass = base64 (str:'admin:cs121-snmp');
useragent = http_get_user_agent();

req = 'GET /admin/net.shtml HTTP/1.0\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Authorization: Basic ' + userpass + '\r\n\r\n';

buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( "Security Settings" >< buf && "Gateway Address" >< buf )
{
  report = 'It was possible to login using "admin" as username and "cs121-snmp" as password.\n';

  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );
