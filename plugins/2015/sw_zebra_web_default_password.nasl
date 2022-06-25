###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_zebra_web_default_password.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Zebra PrintServer Webinterface Default Password
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111060");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Zebra PrintServer Webinterface Default Password");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-11-25 11:00:00 +0100 (Wed, 25 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:'The remote Zebra PrintServer Webinterface is
  prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information.');

  script_tag(name:"vuldetect", value:'Try to login with a default password.');
  script_tag(name:"insight", value:'It was possible to login with default password 1234');
  script_tag(name:"solution", value:'Change the password.');

  script_xref(name:"URL", value:"https://support.zebra.com/cpws/docs/znet2/ps_firm/znt2_pwd.html");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

req = http_get( item: "/settings", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Zebra Technologies" >< res || "Internal Wired PrintServer" >< res || "ENTER PASSWORD" >< res) {

  vuln = 0;
  host = http_host_name( port:port );
  report = '';
  useragent = http_get_user_agent();
  data = string( "0=1234" );
  len = strlen( data );

  req = 'POST /authorize HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Access Granted. This IP Address now has admin" >< res && "access to the restricted printer pages." >< res ) {
    security_message( port:port, data:"It was possible to login using the following password:\n\n1234" );
    exit( 0 );
  }
}

exit( 99 );
