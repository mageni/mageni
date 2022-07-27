# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:semperplugins:all-in-one-seo-pack";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117868");
  script_version("2021-12-22T13:07:15+0000");
  script_tag(name:"last_modification", value:"2021-12-23 11:02:55 +0000 (Thu, 23 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-22 12:52:32 +0000 (Wed, 22 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-25037");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin 4.1.3.1 - 4.1.5.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin All in One SEO Pack is prone to an SQL
  injection (SQLi) vulnerability.");

  script_tag(name:"insight", value:"The PostsTerms::searchForObjects() method, which is accessible
  via the /wp-json/aioseo/v1/objects REST API route only escaped user input using wpdb::esc_like()
  before appending said input to an SQL query. Since this method isn't designed to escape quotes, an
  attacker could still inject them and force the query to leak sensitive information from the
  database, like user credentials.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin version 4.1.3.1 through
  4.1.5.2.");

  script_tag(name:"solution", value:"Update to version 4.1.5.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/all-in-one-seo-pack/#developers");
  script_xref(name:"URL", value:"https://jetpack.com/2021/12/14/severe-vulnerabilities-fixed-in-all-in-one-seo-plugin-version-4-1-5-3/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.1.3.1", test_version2: "4.1.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);