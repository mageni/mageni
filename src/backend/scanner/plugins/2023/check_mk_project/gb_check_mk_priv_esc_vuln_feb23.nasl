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

CPE = "cpe:/a:check_mk_project:check_mk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124277");
  script_version("2023-02-21T10:09:30+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-10 12:03:05 +0000 (Fri, 10 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-43440");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Checkmk < 1.6.0p29, 2.0 < 2.0.0p25, 2.1 < 2.1.0b9, 2.2 < 2.2.0b1 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_check_mk_web_detect.nasl");
  script_mandatory_keys("check_mk/detected");

  script_tag(name:"summary", value:"Checkmk is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"Uncontrolled Search Path Element in Checkmk Agent in Tribe29
  Checkmk server allows the site user to escalate privileges via a manipulated unixcat executable");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Checkmk version prior to 1.6.0p29, 2.0.x prior to 2.0.0p25,
  2.1.x prior to 2.1.0b9 and 2.2.x prior to 2.2.0b1.");

  script_tag(name:"solution", value:"Update to version 1.6.0p29, 2.0.0p25, 2.1.0b9, 2.2.0.b1
  or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-c5gc-w2vf-pmgw");
  script_xref(name:"URL", value:"https://checkmk.com/werk/14087");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.6.0p29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.0p29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.0.0p25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0p25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.1.0", test_version_up: "2.1.0b9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.0b9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "2.2.0", test_version_up: "2.2.0b1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.0b1");
  security_message(port: port, data: report);
  exit(0);
}
exit(99);
