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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143152");
  script_version("2019-11-20T09:34:29+0000");
  script_tag(name:"last_modification", value:"2019-11-20 09:34:29 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-20 09:11:19 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-14884", "CVE-2019-14882", "CVE-2019-14880", "CVE-2019-14879");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.5.9, 3.6.x < 3.6.7, 3.7.x < 3.7.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Moodle is prone to multiple vulnerabilities:

  - Assigned Role in Cohort did not un-assign on removal (CVE-2019-14879)

  - Add additional verification for some OAuth 2 logins to prevent account compromise (CVE-2019-14880)

  - Open redirect in Lesson edit page (CVE-2019-14882)

  - Reflected XSS possible from some fatal error messages (CVE-2019-14884)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.5.9, 3.6.7 or 3.7.3.");

  script_tag(name:"solution", value:"Update to version 3.5.9, 3.6.7, 3.7.3 or later.");

  script_xref(name:"URL", value:"https://moodle.org/security/");

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

if (version_is_less(version: version, test_version: "3.5.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7", test_version2: "3.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
