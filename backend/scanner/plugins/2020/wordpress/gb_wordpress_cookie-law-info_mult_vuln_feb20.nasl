# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112699");
  script_version("2020-02-19T10:41:57+0000");
  script_tag(name:"last_modification", value:"2020-02-19 10:41:57 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-19 10:15:00 +0000 (Wed, 19 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GDPR Cookie Consent Plugin < 1.8.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("cookie-law-info/detected");

  script_tag(name:"summary", value:"The GDPR Cookie Consent plugin for WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The save_contentdata method allows the administrator to save the GDPR cookie notice to the database as a page post type.
  An authenticated user such as a subscriber can use it to put any existing page or post (or the entire website) offline by changing their status.
  Additionally, it is possible to delete or change their content. Injected content can include formatted text,
  local or remote images as well as hyperlinks and shortcodes.

  - The autosave_contant_data method is used to save the GDPR cookie info page while the admin is editing it.
  An authenticated user can use it to inject JavaScript code, which will be loaded and executed each time someone,
  authenticated or not, visits the '/cli-policy-preview/' page.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to inject malicious code into
  an affected site, put the whole site offline or change and delete its contents.");

  script_tag(name:"affected", value:"WordPress GDPR Cookie Consent plugin before version 1.8.3.");

  script_tag(name:"solution", value:"Update to version 1.8.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/cookie-law-infi/#developers");
  script_xref(name:"URL", value:"https://blog.nintechnet.com/wordpress-gdpr-cookie-consent-plugin-fixed-vulnerability/");

  exit(0);
}

CPE = "cpe:/a:webtoffee:cookie-law-info";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
