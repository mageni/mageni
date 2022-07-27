###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_space_webui_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Junos Space Web Management Interface Default Credentials
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105412");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Junos Space Web Management Interface Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-19 12:48:28 +0200 (Mon, 19 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_junos_space_webui_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:'The remote Junos Space Web Management Interface is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: super/juniper123');
  script_tag(name:"solution", value:'Change the password.');
  script_tag(name:"solution_type", value:"Workaround");
  script_mandatory_keys("junos_space_webui/installed");

  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe = 'cpe:/a:juniper:junos_space';


if( ! port = get_app_port( cpe:cpe ) ) exit( 0 );

url = '/mainui/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
if( isnull( cookie[1] ) ) exit( 0 );

co = cookie[1];

if( "Junos Space Login</title>" >!< buf || "j_username" >!< buf ) exit( 0 );
useragent = http_get_user_agent();
user = 'super';
pass = 'juniper123';

_ip = eregmatch( pattern:"ipAddr = '([^']+)'", string:buf );
if( ! isnull( _ip[1] ) ) ip = _ip[1];

_code = eregmatch( pattern:"code = '([^']+)'", string:buf );
if( ! isnull( _code[1] ) ) code = _code[1];

if( isnull( ip ) )
  data = 'j_username=' + user;
else
  data = 'j_username=' + user + '%25' + code + '%40' + ip;

data += '&j_screen_username=' + user + '&j_password=' + pass;

len = strlen( data );

host = http_host_name( port:port );

req = 'POST /mainui/j_security_check HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'DNT: 1\r\n' +
      'Referer: http://' + host + '/mainui/\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

req = 'GET /mainui/ HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Encoding: identity\r\n' +
      'DNT: 1\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      '\r\n';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "/mainui/?bid=" >!< buf ) exit( 99 );

_bid = eregmatch( pattern:'/mainui/\\?bid=([^\r\n; ]+)', string:buf );

if( isnull( _bid[1] ) ) exit( 0 );

bid = _bid[1];

url = '/mainui/?bid=' + bid;

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Encoding: identity\r\n' +
      'DNT: 1\r\n' +
      'Cookie: ' + co + '\r\n' +
      'Connection: close\r\n' +
      '\r\n';

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Junos Space Network Management Platform" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

