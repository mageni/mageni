# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:facebook:hhvm";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108639");
  script_version("2019-09-09T11:16:48+0000");
  script_tag(name:"last_modification", value:"2019-09-09 11:16:48 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-09 10:57:23 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-11925", "CVE-2019-11926");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HHVM Multiple Vulnerabilities - Sep19");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hhvm_detect.nasl");
  script_mandatory_keys("HHVM/detected");

  script_tag(name:"summary", value:"HHMV is prone to multiple memory overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a possible memory overflow in the GD extension
  when a carefully constructed invalid JPEG input is passed in.");

  script_tag(name:"solution", value:"Update to version  3.30.10, 4.8.4, 4.15.3, 4.16.4, 4.17.3, 4.18.2,
  4.19.1, 4.20.2, 4.21.0 or later.");

  script_xref(name:"URL", value:"https://hhvm.com/blog/2019/09/03/security-update.html");
  script_xref(name:"URL", value:"https://www.facebook.com/security/advisories/cve-2019-11925");
  script_xref(name:"URL", value:"https://www.facebook.com/security/advisories/cve-2019-11926");
  script_xref(name:"URL", value:"https://github.com/facebook/hhvm/commit/f1cd34e63c2a0d9702be3d41462db7bfd0ae7da3");
  script_xref(name:"URL", value:"https://github.com/facebook/hhvm/commit/f9680d21beaa9eb39d166e8810e29fbafa51ad15");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "3.30.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.30.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.8.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.9.0", test_version2: "4.15.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.16.0", test_version2: "4.16.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.16.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.17.0", test_version2: "4.17.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.17.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.18.0", test_version2: "4.18.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.18.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.19.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.20.0", test_version2: "4.20.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.20.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
