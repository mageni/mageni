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

CPE = "cpe:/a:ninjaforms:contact_form";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127070");
  script_version("2022-07-07T10:16:06+0000");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 11:47:11 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:P/A:N");

  script_cve_id("CVE-2021-25056", "CVE-2021-25066");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ninja Forms Contact Form Plugin < 3.6.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ninja-forms/detected");

  script_tag(name:"summary", value:"The Ninja Forms Contact Form plugin for WordPress is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-25056: The plugin does not sanitise and escape field labels, allowing high privilege
  users to perform cross-site scripting attacks even when the unfiltered_html capability is
  disallowed.

  - CVE-2021-25066:The plugin does not sanitize and escape some imported data, allowing high
  privilege users to perform cross-site scripting attacks even when the unfiltered_html capability
  is disallowed.");

  script_tag(name:"affected", value:"WordPress Ninja Forms Contact Form plugin prior to version
  3.6.10.");

  script_tag(name:"solution", value:"Update to version 3.6.10 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/795acab2-f621-4662-834b-ebb6205ef7de");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/323d5fd0-abe8-44ef-9127-eea6fd4f3f3d");

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

if (version_is_less(version: version, test_version: "3.6.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
