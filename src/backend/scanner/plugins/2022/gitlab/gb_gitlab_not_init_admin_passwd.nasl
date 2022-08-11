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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117994");
  script_version("2022-03-07T13:06:38+0000");
  script_tag(name:"last_modification", value:"2022-03-08 11:27:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-07 12:11:38 +0000 (Mon, 07 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("GitLab Uninitialized Admin Password (HTTP) - Active Check");

  script_category(ACT_GATHER_INFO); # nb: Just a request which would be done by a user so no ACT_ATTACK

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_http_detect.nasl");
  script_mandatory_keys("gitlab/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"The remote GitLab instance is not initialized with an admin
  password.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated remote user might finish the setup of the
  remote GitLab instance and take full control over it.");

  script_tag(name:"affected", value:"GitLab in all versions prior to 14.0 if the initial admin
  password was not set-up during the instance installation.");

  script_tag(name:"solution", value:"Finish the instance setup by setting an admin password.");

  script_xref(name:"URL", value:"https://docs.gitlab.com/omnibus/installation/#set-up-the-initial-password");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/5331");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

curr_dir = dir;
if( dir == "/" )
  dir = "";

url = dir + "/users/sign_in";

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res || res !~ "^HTTP/1\.[01] 302" || res !~ "Set-Cookie\s*:\s*_gitlab_session=[^;]+" )
  exit( 0 );

if( ! loc = http_extract_location_from_redirect( port:port, data:res, current_dir:curr_dir ) )
  exit( 0 );

if( "/users/password/edit" >!< loc )
  exit( 0 );

if( ! cookie = http_get_cookie_from_header( buf:res, pattern:"(_gitlab_session=[^; ]+)" ) )
  exit( 0 );

req = http_get_req( port:port, url:loc, add_headers:make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port:port, data:req );
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

# Different responses (probably different versions).
#
# Instance 1:
# <input class="form-control top" placeholder="New password" required="required" type="password" name="user[password]" id="user_password" />
# <input class="form-control bottom" placeholder="Confirm new password" required="required" type="password" name="user[password_confirmation]" id="user_password_confirmation" />
# <input type="submit" name="commit" value="Change your password" class="btn btn-primary" />
#
# Instance 2:
# nb: This had the "form-control" but not the "placeholder" text included:
# <label for="user_password">New password</label>
# <label for="user_password_confirmation">Confirm new password</label>
# <input type="submit" name="commit" value="Change your password" class="btn btn-primary" data-qa-selector="change_password_button" data-disable-with="Change your password" />
#
if( res =~ '[">]New password["<]' &&
    res =~ '[">]Confirm new password["<]' &&
    res =~ '[">]Change your password["<]' ) {
  report  = "Vulnerable URLs:";
  report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  report += '\n' + http_report_vuln_url( port:port, url:loc, url_only:TRUE );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
