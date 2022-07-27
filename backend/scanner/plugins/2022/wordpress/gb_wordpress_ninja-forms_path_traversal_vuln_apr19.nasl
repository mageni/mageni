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

CPE = "cpe:/a:ninjaforms:ninja_forms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124068");
  script_version("2022-06-10T03:04:13+0000");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-10 06:50:43 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-02 19:34:00 +0000 (Mon, 02 May 2022)");

  script_cve_id("CVE-2019-10869");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ninja Forms Plugin < 3.0.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ninja-forms/detected");

  script_tag(name:"summary", value:"The Ninja Forms plugin for WordPress is prone to a path
  traversal and unrestricted file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows an attacker to traverse the file system to
  access files and execute code via the includes/fields/upload.php (aka upload/submit page) name
  and tmp_name parameters.");

  script_tag(name:"affected", value:"WordPress Ninja Forms plugin prior to version 3.0.23");

  script_tag(name:"solution", value:"Update to version 3.0.23 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9272");
  script_xref(name:"URL", value:"https://www.onvio.nl/nieuws/ninjaforms-vulnerability");

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

if (version_is_less(version: version, test_version: "3.0.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
