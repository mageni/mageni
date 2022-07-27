###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apc_web_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# APC Network Management Card Webinterface Default Credentials
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111052");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("APC Network Management Card Webinterface Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-11-12 15:00:00 +0100 (Thu, 12 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:'The remote APC Network Management Card Webinterface is
  prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');

  script_tag(name:"insight", value:'It was possible to login with default credentials of apc:apc,
  device:apc or readonly:device.');

  script_tag(name:"solution", value:'Change the password.');

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
useragent = http_get_user_agent();
res = http_get_cache( item:"/logon.htm", port:port );

if( "APC Website" >< res || "http://www.apc.com" >< res || "<title>APC | Log On</title>" >< res ) {

  vuln = FALSE;
  host = http_host_name( port:port );
  report = 'It was possible to login using the following credentials:';

  creds = make_array( "apc", "apc",
                      "device", "apc",
                      "readonly", "apc" );

  foreach cred ( keys( creds ) ) {

    data = string( "login_username=" + cred + "&login_password=" + creds[cred] + "&submit=Log+On" );
    len = strlen( data );

    req = 'POST /Forms/login1 HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          'Cookie: C0=apc; chkcookie=' + unixtime() + '\r\n' +
          '\r\n' +
          data;
    res = http_keepalive_send_recv( port:port, data:req );

    cookie = eregmatch( pattern:"Set-Cookie:APC([0-9a-zA-Z]+)=([0-9a-zA-Z+]+);", string:res );
    if( isnull( cookie[1] ) ) {
      cookie = eregmatch( pattern:"Set-Cookie: C0=([0-9a-zA-Z+]+);", string:res );
      if( isnull( cookie[1] ) ) {
        cookie = "C0=apc";
      } else {
        cookie = "C0=" + cookie[1];
      }
    } else {
      cookie = "APC" + cookie[1] + '=' + cookie[2];
    }

    redirect = eregmatch( pattern:"/NMC/([0-9a-zA-Z+]+)/", string:res );
    if( isnull( redirect[1] ) ) {
      redirect = "/";
    } else {
      redirect = "/NMC/" + redirect[1] + "/";
    }

    req = 'GET ' + redirect + 'home.htm HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Cookie: ' + cookie + '\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );

    if( '<a href="logout.htm"' >< res && "Log Off" >< res) {
      report += '\n\n' + cred + ":" + creds[cred] + '\n';
      vuln = TRUE;
    }

    # Logoff to avoid locking the webinterface for other users
    req = 'GET ' + redirect + 'logout.htm HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Cookie: ' + cookie + '\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
