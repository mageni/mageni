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

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104364");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 11:10:25 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-21618", "CVE-2022-39399");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK Multiple Vulnerabilities (Oct 2022 - 01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the
  vulnerabilities.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 11, 13, 15, 17 and 19.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2022-10-18");
  script_xref(name:"URL", value:"https://mail.openjdk.org/pipermail/vuln-announce/2022-October/000017.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (vers =~ "^11\." && version_is_less(version: vers, test_version: "11.0.17")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.0.17", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^13\." && version_is_less(version: vers, test_version: "13.0.13")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "13.0.13", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^15\." && version_is_less(version: vers, test_version: "15.0.9")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "15.0.9", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^17\." && version_is_less(version: vers, test_version: "17.0.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "17.0.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (vers =~ "^19\." && version_is_less(version: vers, test_version: "19.0.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "19.0.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
