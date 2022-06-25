# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146970");
  script_version("2021-10-22T08:03:31+0000");
  script_tag(name:"last_modification", value:"2021-10-22 10:34:07 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-03-16 13:52:40 +0000 (Tue, 16 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-05 18:22:00 +0000 (Wed, 05 Aug 2020)");

  script_cve_id("CVE-2020-13699");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TeamViewer Unqoted URI Handler Vulnerability (CVE 2020-13699) - Windows");

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  script_tag(name:"summary", value:"TeamViewer is prone to an unquoted URI handler vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TeamViewer Desktop for Windows does not properly quote its
  custom URI handlers. A malicious website could launch TeamViewer with arbitrary parameters.");

  script_tag(name:"impact", value:"An attacker could force a victim to send an NTLM authentication
  request and either relay the request or capture the hash for offline password cracking.");

  script_tag(name:"affected", value:"TeamViewer prior to version 15.8.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 8.0.258861, 9.0.258860, 10.0.258873,
  11.0.258870, 12.0.258869, 13.2.36220, 14.2.56676, 14.7.48350, 15.8.3 or later.");

  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/98448/statement-on-cve-2020-13699");
  script_xref(name:"URL", value:"https://jeffs.sh/CVEs/CVE-2020-13699.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.0.258861")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.258861", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0", test_version2: "9.0.258859")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.258860", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.0.258872")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.258873", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.0.258869")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.258870", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.258868")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.258869", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.2.36219")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.2.36220", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.2.56675")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.2.56676", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15.0", test_version2: "15.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.8.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
