# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124261");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-01-25 11:31:42 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2023-23921", "CVE-2023-23923");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 3.9 <= 3.9.18, 3.11 <= 3.11.11, 4.0 <= 4.0.5, 4.1 < 4.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-23-0001, CVE-2023-23921: Reflected XSS risk in some returnurl parameters

  - MSA-23-0003, CVE-2023-23923: Possible to set the preferred 'start page' of other users");

  script_tag(name:"affected", value:"Moodle versions 3.9 through 3.9.18, 3.11 through 3.11.11,
  4.0 through 4.0.5 and 4.1 prior to 4.1.1.");

  script_tag(name:"solution", value:"Update to version 3.9.19, 3.11.12, 4.0.6, 4.1.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=443272");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=443274");

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

if (version_in_range(version: version, test_version: "3.9", test_version2: "3.9.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.11", test_version2: "3.11.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
