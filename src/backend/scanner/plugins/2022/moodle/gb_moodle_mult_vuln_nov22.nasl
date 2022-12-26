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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126236");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-29 08:10:25 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-45149", "CVE-2022-45150", "CVE-2022-45152");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.18, 3.11.x < 3.11.11, 4.x < 4.0.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-22-0029 / CVE-2022-45149: A user's CSRF token was unnecessarily included in the URL when
  being redirected to a course they have just restored.

  - MSA-22-0030 / CVE-2022-45150: The return URL in the policy tool required extra sanitizing to
  prevent a reflected XSS risk.

  - MSA-22-0032 / CVE-2022-45152: Moodle's LTI provider library did not utilise Moodle's inbuilt
  cURL helper, which resulted in a blind SSRF risk.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.18, 3.11.x through 3.11.10 and 4.x
  through 4.0.4.");

  script_tag(name:"solution", value:"Update to version 3.9.18, 3.11.11, 4.0.5 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=440769");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=440770");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=440772");

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

if (version_is_less(version: version, test_version: "3.9.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.11.0", test_version2: "3.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
