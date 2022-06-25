# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113840");
  script_version("2022-03-16T14:35:02+0000");
  script_tag(name:"last_modification", value:"2022-03-17 11:18:10 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-16 13:25:23 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MantisBT Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_dependencies("gb_mantisbt_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mantisbt/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.mantisbt.org/docs/master/en-US/Admin_Guide/html-desktop/#admin.install.postinstall");

  script_tag(name:"summary", value:"The remote MantisBT instance is using known default credentials
  for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"All MantisBT instances with default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

creds = make_array();
creds["administrator"] = "root";

url = dir + "/login.php";
report = "It was possible to login at '" + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + "' with the following known default credentials:";

foreach username( keys( creds ) ) {

  password = creds[username];

  # nb: Note that changing the "return=index.php" would change some of the responses below.
  data = "return=index.php&username=" + username + "&password=" + password;

  req = http_post_put_req( port:port, url:url, data:data, add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res || res !~ "^HTTP/1\.[01] 302" )
    continue;

  # nb: We're getting a 302 redirect (on both, failed and successful login) including e.g. the
  # following below. Note that in both cases a PHPSESSID is set which can't be used for detection.
  #
  # Version 2.22.1
  #
  # Successful login:
  # Set-Cookie: MANTIS_secure_session=0; path=/; httponly
  # Set-Cookie: MANTIS_STRING_COOKIE=4cbaef2c66ca66ce35b59dc934416b014af4b8081d9376cfc242b051d6aee56c; path=/; httponly
  # Location: http://example.com/login_cookie_test.php?return=account_page.php
  #
  # Failed login (no MANTIS_STRING_COOKIE):
  # Set-Cookie: MANTIS_secure_session=0; path=/; httponly
  # Location: http://example.com/login_page.php?error=1&username=administrator&return=index.php
  #
  # Version 1.2.19
  #
  # Successful login:
  # Set-Cookie: MANTIS_secure_session=0; path=/; secure; httponly
  # Set-Cookie: MANTIS_STRING_COOKIE=7ad6c82aae58d66a29992dc97cc72ae4540173f2f6d0071f187d33fa7854bb5c; path=/; secure; httponly
  # Location: http://example.com/login_cookie_test.php?return=index.php
  #
  # Failed login (no MANTIS_STRING_COOKIE):
  # Set-Cookie: MANTIS_secure_session=0; path=/; secure; httponly
  # Location: http://example.com/login_page.php?return=index.php&error=1&username=administrator&secure_session=0&perm_login=0
  #
  if( found = egrep( string:res, pattern:"^([Ss]et-[Cc]ookie\s*:\s*MANTIS_STRING_COOKIE=.+|[Ll]ocation\s*:.*/login_cookie_test\.php\?return=(index|account_page)\.php)", icase:FALSE ) ) {
    found = chomp( found );
    report += '\n\nUsername: ' + username + '\nPassword: ' + password + '\nResponse:\n' + found;
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
