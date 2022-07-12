# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117075");
  script_version("2020-12-11T14:21:37+0000");
  script_tag(name:"last_modification", value:"2020-12-14 11:01:00 +0000 (Mon, 14 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-11 13:44:24 +0000 (Fri, 11 Dec 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("D-Link DSR Devices Default Login (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_dlink_dsr_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("Host/is_d-link_dsr_device");
  script_require_ports("Services/www", 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote D-Link DSR device is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"All D-Link DSR devices with default credentials.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

if( ! get_kb_item( "d-link/has_scgi-bin_platform.cgi" ) )
  exit( 0 ); # nb: Currently only supporting devices with that endpoint.

CPE_PREFIX = "cpe:/o:d-link";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");
include("misc_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

port = infos["port"];
CPE = infos["cpe"];

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

username = "admin";
password = "admin";

url = "/scgi-bin/platform.cgi";
ua = http_get_user_agent();
ua = urlencode( str:ua );

# e.g. thispage=index.html&Users.UserName=admin&Users.Password=admin&button.login.Users.dashboard=Login&Login.userAgent=Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F83.0.4103.116+Safari%2F537.36&loggedInStatus=
data = "thispage=index.html&Users.UserName=" + username + "&Users.Password=" + password + "&button.login.Users.dashboard=Login&Login.userAgent=" + ua + "&loggedInStatus=";

# nb: Referer is required, the device will respond with an "invalid referer" if not given.
req = http_post_put_req( port:port, url:url, data:data, referer_url:url, add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );

if( ( "<p>User Already Logged In</p>" >< res && "If you want to close the other session, please click on" >< res ) || # nb: Happens if a session is already open / a user is logged in
    ( ( "Logged in as:" >< res && "admin" >< res ) ||
      ( 'class="btnLogout"' >< res && ( "?page=lanSettings.html" >< res || "?page=deviceInfo.html" >< res ) ) ) ) {
  report = "It was possible to login with username '" + username + "' and password '" + password + "'.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
