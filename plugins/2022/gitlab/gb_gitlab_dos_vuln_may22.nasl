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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148092");
  script_version("2022-05-11T07:31:32+0000");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 03:58:27 +0000 (Wed, 11 May 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2022-1431");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 12.10.x < 14.8.6, 14.9.x < 14.9.4, 14.10.x < 14.10.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GitLab is not correctly handling malicious requests to the PyPi
  API endpoint allowing the attacker to cause uncontrolled resource consumption.");

  script_tag(name:"affected", value:"GitLab version 12.10.x prior to 14.8.6, 14.9.x prior to 14.9.4
  and 14.10.x prior to 14.10.1.");

  script_tag(name:"solution", value:"Update to version 14.8.6, 14.9.4, 14.10.1 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1431.json");
  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "12.10.0", test_version_up: "14.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.8.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.9.0", test_version_up: "14.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.9.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.10.0", test_version_up: "14.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
