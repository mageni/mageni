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
  script_oid("1.3.6.1.4.1.25623.1.0.147149");
  script_version("2021-11-15T03:28:41+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-15 03:27:44 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-23214", "CVE-2021-23222");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL < 9.6.24, 10.x < 10.19, 11.x < 11.14, 12.x < 12.9, 13.x < 13.5, 14.x < 14.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-23214: Server processes unencrypted bytes from man-in-the-middle

  - CVE-2021-23222: libpq processes unencrypted bytes from man-in-the-middle");

  script_tag(name:"affected", value:"PostgreSQL prior to version 9.6.24, version 10.x through 10.18,
  11.x through 11.13, 12.x through 12.8, 13.x through 13.4 and version 14.0.");

  script_tag(name:"solution", value:"Update to version 9.6.24, 10.19, 11.14, 12.9, 13.5, 14.1 or
  later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-141-135-129-1114-1019-and-9624-released-2349/");

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

if (version_is_less(version: version, test_version: "9.6.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
