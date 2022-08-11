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

CPE = "cpe:/a:freeipa:freeipa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143217");
  script_version("2019-12-04T05:43:50+0000");
  script_tag(name:"last_modification", value:"2019-12-04 05:43:50 +0000 (Wed, 04 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-04 04:27:48 +0000 (Wed, 04 Dec 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-10195", "CVE-2019-14867");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreeIPA Multiple Vulnerabilities - Nov19");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freeipa_detect.nasl");
  script_mandatory_keys("freeipa/detected");

  script_tag(name:"summary", value:"FreeIPA is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"FreeIPA is prone to multiple vulnerabilities:

  - Information disclosure vulnerability (CVE-2019-1019)

  - Denial of service and possible remote code execution vulnerability (CVE-2019-14867)");

  script_tag(name:"affected", value:"FreeIPA version 4.6.x, 4.7.x and 4.8.x.");

  script_tag(name:"solution", value:"Update to version 4.6.7, 4.7.4, 4.8.3 or later.");

  script_xref(name:"URL", value:"https://www.freeipa.org/page/Releases/4.6.7");
  script_xref(name:"URL", value:"https://www.freeipa.org/page/Releases/4.7.4");
  script_xref(name:"URL", value:"https://www.freeipa.org/page/Releases/4.8.3");

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

if (version_in_range(version: version, test_version: "4.6", test_version2: "4.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.7", test_version2: "4.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.7.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.8", test_version2: "4.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
