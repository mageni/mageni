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

CPE = "cpe:/a:webfactoryltd:wp_reset";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127123");
  script_version("2022-08-08T08:41:53+0000");
  script_tag(name:"last_modification", value:"2022-08-08 08:41:53 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-05 09:15:52 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-19 21:56:00 +0000 (Fri, 19 Nov 2021)");

  script_cve_id("CVE-2021-36908", "CVE-2021-36909");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Reset PRO Plugin <= 5.98 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-reset/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Reset PRO' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-36908: The plugin allows cross-site request forgery (CSRF) vulnerability that leads to
  database reset.

  - CVE-2021-36909: The plugin allows any authenticated user to wipe the entire database regardless
  of their authorization.");

  script_tag(name:"affected", value:"WordPress 'WP Reset PRO' plugin version 5.98 and prior.");

  script_tag(name:"solution", value:"Update to version 5.99 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-reset/wordpress-wp-reset-pro-premium-plugin-5-98-cross-site-request-forgery-csrf-vulnerability-leading-to-database-reset");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/wp-reset/wordpress-wp-reset-pro-premium-plugin-5-98-authenticated-database-reset-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/articles/wp-reset-pro-critical-vulnerability-fixed/");

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

if (version_is_less_equal(version: version, test_version: "5.98")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.99", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
