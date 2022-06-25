###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuuo_nvr_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# NUUO Network Video Recorder Devices Default Credentials
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112328");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-07-17 11:26:00 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-6553");
  script_bugtraq_id(93807);

  script_name("NUUO Network Video Recorder Devices Default Credentials");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_require_ports("Services/www", 8081);
  script_mandatory_keys("nuuo/web/detected");

  script_tag(name:"solution", value:"Nuuo has released an update to address the issue. Please see the vendor information.

  As a general good security practice, only allow trusted hosts to connect to the device.
  Use of strong, unique passwords can help reduce the efficacy of brute force password guessing attacks.");

  script_tag(name:"summary", value:"NUUO Network Video Recorder devices have default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

cookie = get_kb_item("nuuo/web/cookie");
if( isnull( cookie ) ) exit( 0 );

# GET request to fetch a fresh cookie
req = http_get( port:port , item:"/" );
res = http_keepalive_send_recv( port:port, data:req );

cookie_match = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:res );
if( cookie_match[1] ){
  cookie = cookie_match[1];
} else {
  exit(0);
}

vuln = FALSE;
report = "";  # nb: To make openvas-nasl-lint happy...

credentials = make_list( "admin:admin", "localdisplay:111111" );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach credential( credentials ) {

  user_pass = split( credential, sep:":", keep:FALSE );

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  if( tolower( pass ) == "none" ) pass = "";

  data = string( 'language=en&user=' + user + '&pass=' + pass + '&submit=Login' );
  len = strlen( data );

  req = 'POST /login.php HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Referer: http://' + host + '/login.php/\r\n' +
        'Cookie: ' + cookie + '\r\n' +
        'Connection: keep-alive\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "HTTP/1.. 302" && "/setting.php" >< res ) {

    req = 'GET /setting.php HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Referer: http://' + host + '/setting.php\r\n' +
          'Cookie: ' + cookie + '\r\n' +
          'Connection: keep-alive\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );

    if( '<span class="productName">' >< res || '<div id="official_fw_ver">' >< res ) {
      vuln = TRUE;
      report += 'It was possible to login into the NUUO Network Video Recorder Administration at ' + report_vuln_url( port:port, url:'/login.php', url_only:TRUE ) + ' using user "' + user + '" with password "' + pass + '".\r\n';
      product_match = eregmatch( pattern:'<span class="productName">([A-Z0-9-]+)</span>', string:res );

      if( product_match[1] ) {
        product = product_match[1];
      }
    }
  }
}

# nb: This is placed outside the loop to not be reported multiple times if multiple logins were possible.
if( product ) {
  set_kb_item(name:'nuuo/model', value:product);
  report += '\r\nThe running device is a NUUO ' + product + '.';
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );