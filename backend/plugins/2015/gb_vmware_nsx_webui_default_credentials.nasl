###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_nsx_webui_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Vmware NSX Web Management Interface Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.105423");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Vmware NSX Web Management Interface Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-27 16:29:45 +0100 (Tue, 27 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_nsx_webgui_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:'The remote Vmware NSX Web Management Interface is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: admin/default');
  script_tag(name:"solution", value:'Change the password.');
  script_mandatory_keys("vmware_nsx/webui");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_kb_item("vmware_nsx/webui/port") ) exit( 0 );

buf = http_get_cache( item:'/login.jsp', port:port );

cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
if( isnull( cookie[1] ) ) exit( 0 );

co = cookie[1];

data = 'j_username=admin&j_password=default&submit=';
len = strlen( data );

host = http_host_name( port:port );
useragent = http_get_user_agent();

req = 'POST /j_spring_security_check HTTP/1.1\r\n' +
      'Connection: Close\r\n' +
      'Host: ' + host + '\r\n' +
      'Pragma: no-cache\r\n' +
      'Cache-Control: no-cache\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' +
      'Accept-Language: en\r\n' +
      'Accept-Charset: iso-8859-1,*,utf-8\r\n' +
      'Cookie: ' + co  + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;

res = http_keepalive_send_recv( port:port, data:req );

_sess = eregmatch( pattern:'JSESSIONID=([^ ;\r\n]+)', string:res );
if( isnull( _sess[1] ) ) exit( 0 );

session = _sess[1];

XSRF_TOKEN = eregmatch( pattern:'XSRF-TOKEN=([^\r\n]+)', string:res);
if( isnull( XSRF_TOKEN[1] ) ) exit( 99 );

co = 'JSESSIONID=' + session + '; XSRF-TOKEN=' + XSRF_TOKEN[1];

if( http_vuln_check( port:port, url:'/index.html', pattern:"/manage/settings/general", cookie:co ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

