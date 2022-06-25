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

CPE = "cpe:/a:variation_swatches_for_woocommerce_project:variation_swatches_for_woocommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124069");
  script_version("2022-06-10T03:04:13+0000");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-10 11:00:00 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-17 01:56:00 +0000 (Fri, 17 Dec 2021)");

  script_cve_id("CVE-2021-42367");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Variation Swatches for WooCommerce Plugin < 2.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/woo-variation-swatches/detected");

  script_tag(name:"summary", value:"The WooCommerce plugin for WordPress is prone to an cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Variation Swatches for WooCommerce WordPress plugin is
  vulnerable to stored XSS via several parameters found in the ~/includes/class-menu-page.php file
  which allows attackers to inject arbitrary web scripts. Due to missing authorization checks on
  the tawcvs_save_settings function, low-level authenticated users such as subscribers can exploit
  this vulnerability.");

  script_tag(name:"affected", value:"WordPress Variation Swatches for WooCommerce Plugin prior to
  version 2.1.2");

  script_tag(name:"solution", value:"Update to version 2.1.2 or later");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2021-42367");

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

if (version_is_less(version: version, test_version: "2.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
