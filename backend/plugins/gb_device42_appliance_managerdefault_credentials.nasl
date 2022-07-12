###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_device42_appliance_managerdefault_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Device42 DCIM Appliance Manager Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.105123");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Device42 DCIM Appliance Manager Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-11-28 12:02:06 +0200 (Fri, 28 Nov 2014)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4242);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:'The remote Device42 DCIM Appliance Manager web interface
  is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: d42admin/default');
  script_tag(name:"solution", value:'Change the password.');

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:4242 );

url = '/accounts/login/';
buf = http_get_cache( item:url, port:port );

if( "<title>Device42 Appliance Manager" >!< buf ) exit( 0 );

csrf_token = eregmatch( pattern:'csrftoken=([^; ]+)', string:buf );
if( isnull( csrf_token[1] ) ) exit( 0 );

csrf = csrf_token[1];

d42amid_token = eregmatch( pattern:'d42amid=([^; ]+)', string:buf );
if( isnull( d42amid_token[1] ) ) exit( 0 );

d42amid = d42amid_token[1];

login_data = 'csrfmiddlewaretoken=' + csrf  + '&username=d42admin&password=default&next=%2F';
len = strlen( login_data );

host = http_host_name( port:port );
useragent = http_get_user_agent();

req = 'POST /accounts/login/ HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Referer: http://' +  host + ':' + port + '/accounts/login/?next=/\r\n' +
      'Cookie: csrftoken=' + csrf  + '; d42amid=' + d42amid + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      login_data;

buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( buf !~ "HTTP/1\.. 302" || "d42amid" >!< buf ) exit( 0 );

d42amid_token1 =  eregmatch( pattern:'d42amid=([^; ]+)', string:buf );
if( isnull( d42amid_token1[1] ) ) exit( 0 );

d42amid1 = d42amid_token1[1];

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
      'Cookie: d42amid=' + d42amid1 + '\r\n' +
      '\r\n';

result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ">Change password<" >< result && ">Sign Out<" >< result )
{
  set_kb_item( name:'device42/csrf', value: csrf );
  set_kb_item( name:'device42/d42amid', value: d42amid1 );
  set_kb_item( name:'device42/port', value: port );
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

