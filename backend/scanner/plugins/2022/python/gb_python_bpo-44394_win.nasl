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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113934");
  script_version("2022-04-21T12:59:54+0000");
  script_tag(name:"last_modification", value:"2022-04-22 10:21:31 +0000 (Fri, 22 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-21 12:40:42 +0000 (Thu, 21 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-0340");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python DoS Vulnerability (bpo-44394) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On Windows and macOS, Python uses a vendored copy of libexpat
  which is vulnerable to the XML 'Billion Laughs' expansion denial of service attack.

  Updating libexpat copy in Python to libexpat 2.4.0 or newer fix the vulnerability.");

  script_tag(name:"affected", value:"Python versions prior to 3.6.15, 3.7.x prior to 3.7.12, 3.8.x
  prior to 3.8.12 and 3.9.x prior to 3.9.7.");

  script_tag(name:"solution", value:"Update to version 3.6.15, 3.7.12, 3.8.12, 3.9.7, 3.10.0 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/expat-billion-laughs.html");
  script_xref(name:"Advisory-ID", value:"bpo-44394");

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

if (version_is_less(version: version, test_version: "3.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.7.0", test_version_up: "3.7.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
