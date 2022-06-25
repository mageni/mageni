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
  script_oid("1.3.6.1.4.1.25623.1.0.113693");
  script_version("2020-05-20T10:21:59+0000");
  script_tag(name:"last_modification", value:"2020-05-25 10:43:28 +0000 (Mon, 25 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 10:07:04 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2019-20798", "CVE-2019-20799", "CVE-2019-20800");

  script_name("Cherokee Web Server <= 1.2.104 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cherokee_http_detect.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"summary", value:"Cherokee Web Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-Site scripting (XSS) vulnerability in handler_server_info.c.

  - Multiple memory corruption errors may be used by an attacker
    to destabilize the work of a server.

  - Remote attackers can trigger an out-of-bounds write in
    cherokee_handler_cgi_add_env_pair in handler_cgi.c
    by sending many request headers in a single GET request.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to prevent
  other users from accessing the application. inject arbitrary HTML or JavaScript into the site
  or even gain control over the target system.");

  script_tag(name:"affected", value:"Cherokee Web Server through version 1.2.104.");

  script_tag(name:"solution", value:"Update from the source code repository found in the references.");

  script_xref(name:"URL", value:"https://logicaltrust.net/blog/2019/11/cherokee.html");
  script_xref(name:"URL", value:"https://github.com/cherokee/webserver");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.2.104" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Update from source", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
