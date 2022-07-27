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

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108614");
  script_version("2019-08-01T08:03:52+0000");
  script_tag(name:"last_modification", value:"2019-08-01 08:03:52 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 07:53:57 +0000 (Thu, 01 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2019-10127", "CVE-2019-10128");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only PostgreSQL installed via the BigSQL and EnterpriseDB Windows installer are affected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 9.4.x < 9.4.22, 9.5.x < 9.5.17, 9.6.x < 9.6.13, 10.x < 10.8, 11.x < 11.3 Code Execution Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to an arbitrary code execution vulnerability due to
  BigSQL and EnterpriseDB Windows installer not clearing permissive ACL entries.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to both the EnterpriseDB and BigSQL Windows installers not locking down
  the permissions of the PostgreSQL binary installation directory and the data directory, an unprivileged Windows
  user account and an unprivileged PostgreSQL account could cause the PostgreSQL service account to execute arbitrary code.

  This vulnerability is present in all supported versions of PostgreSQL for these installers, and possibly exists
  in older versions. Both sets of installers have fixed the permissions for these directories for both new and existing
  installations. If you have installed PostgreSQL on Windows using other methods, we advise that you check that your
  PostgreSQL binary directories are writable only to trusted users and that your data directories are only accessible
  to trusted users.");

  script_tag(name:"affected", value:"PostgreSQL versions 9.4.x, 9.5.x, 9.6.x, 10.x and 11.x installed on Windows via
  BigSQL or EnterpriseDB installer.");

  script_tag(name:"solution", value:"Update to version 9.4.22, 9.5.17, 9.6.13, 10.8, 11.3 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1939/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_in_range(version: version, test_version: "9.4", test_version2: "9.4.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5", test_version2: "9.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.6", test_version2: "9.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
