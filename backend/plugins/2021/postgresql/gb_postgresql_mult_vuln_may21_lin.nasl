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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146061");
  script_version("2021-09-20T08:40:49+0000");
  script_tag(name:"last_modification", value:"2021-09-21 10:10:27 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-06-02 07:23:49 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 10:15:00 +0000 (Tue, 13 Jul 2021)");

  script_cve_id("CVE-2021-32027", "CVE-2021-32028");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 9.6.x < 9.6.22, 10.x < 10.17, 11.x < 11.12, 12.x < 12.7, 13.x < 13.3 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-32027: While modifying certain SQL array values, missing bounds checks let
  authenticated database users write arbitrary bytes to a wide area of server memory.

  - CVE-2021-32028: Using an INSERT ... ON CONFLICT ... DO UPDATE command on a purpose-crafted
  table, an attacker can read arbitrary bytes of server memory. In the default configuration, any
  authenticated database user can create prerequisite objects and complete this attack at will. A
  user lacking the CREATE and TEMPORARY privileges on all databases and the CREATE privilege on all
  schemas cannot use this attack at will.");

  script_tag(name:"affected", value:"PostgreSQL version 9.6.0 through 9.6.21, 10.0 through 10.16,
  11.0 through 11.11, 12.0 through 12.6 and 13.0 through 13.2.");

  script_tag(name:"solution", value:"Update to version 9.6.22, 10.17, 11.12, 12.7, 13.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2021-32027/");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2021-32028/");

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

if (version_in_range(version: version, test_version: "9.6.0", test_version2: "9.6.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);