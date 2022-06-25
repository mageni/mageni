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

CPE = "cpe:/a:wpdeveloper:essential_addons_for_elementor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147776");
  script_version("2022-03-09T03:03:43+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-08 06:52:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 21:17:00 +0000 (Thu, 03 Mar 2022)");

  script_cve_id("CVE-2022-0683");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Addons for Elementor Plugin < 5.0.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-addons-for-elementor-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin Essential Addons for Elementor is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Essential Addons for Elementor Lite WordPress plugin is
  vulnerable to XSS due to insufficient escaping and sanitization of the settings parameter found
  in the ~/includes/Traits/Helper.php file which allows attackers to inject arbitrary web scripts
  onto a pages that executes whenever a user clicks on a specially crafted link by an attacker.");

  script_tag(name:"affected", value:"WordPress Essential Addons for Elementor plugin prior to
  version 5.0.9.");

  script_tag(name:"solution", value:"Update to version 5.0.9 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-0683");

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

if (version_is_less(version: version, test_version: "5.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
