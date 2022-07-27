# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113660");
  script_version("2020-03-26T13:10:48+0000");
  script_tag(name:"last_modification", value:"2020-03-27 10:13:45 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 12:46:30 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10385");

  script_name("WordPress WPForms Contact Form Plugin < 1.5.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wpforms-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin WPForms Contact Form is vulnerable to
  a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress WPForms Contact Form plugin through version 1.5.8.2.");

  script_tag(name:"solution", value:"Update to version 1.5.9 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wpforms-lite/#developers");
  script_xref(name:"URL", value:"https://www.getastra.com/blog/911/plugin-exploit/stored-xss-vulnerability-found-in-wpforms-plugin/");
  script_xref(name:"URL", value:"https://www.jinsonvarghese.com/stored-xss-vulnerability-found-in-wpforms-plugin/");

  exit(0);
}

CPE = "cpe:/a:wpforms:wpforms-lite";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.5.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.5.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
