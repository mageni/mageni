# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142698");
  script_version("2019-08-06T05:29:15+0000");
  script_tag(name:"last_modification", value:"2019-08-06 05:29:15 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-06 04:58:56 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-10186", "CVE-2019-10187", "CVE-2019-10188", "CVE-2019-10189", "CVE-2018-17057");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.5.7, 3.6.x < 3.6.5, 3.7.x < 3.7.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Moodle is prone to multiple vulnerabilities:

  - A sesskey (CSRF) token is not being utilised by the XML loading/unloading admin tool (CVE-2019-10186)

  - Users with permission to delete entries from a glossary are able to delete entries from other glossaries they
    do not have direct access to (CVE-2019-10187)

  - Teachers in a quiz group can modify group overrides for other groups in the same quiz (CVE-2019-10188)

  - Teachers in an assignment group can modify group overrides for other groups in the same assignment
    (CVE-2019-10189)

  - Upgrade TCPDF library for PHP 7.3 and bug fixes (upstream) (CVE-2018-17057)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.5.7, 3.6.5 or 3.7.1.");

  script_tag(name:"solution", value:"Update to version 3.5.7, 3.6.5, 3.7.1, or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=388567");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=388568");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=388569");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=388570");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=388571");

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

if (version_is_less(version: version, test_version: "3.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
