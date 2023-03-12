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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127027");
  script_version("2023-02-22T10:10:00+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:10:00 +0000 (Wed, 22 Feb 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. To avoid wrong stats about CVE coverage the "creation_date" of the original VT
  # has been kept here because all CVEs had been covered at this time.
  script_tag(name:"creation_date", value:"2022-05-31 09:47:15 +0000 (Tue, 31 May 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-28 02:39:00 +0000 (Sat, 28 May 2022)");

  script_cve_id("CVE-2022-31622", "CVE-2022-31623");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Multiple DoS Vulnerabilities (MDEV-26561) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-31622: in extra/mariabackup/ds_compress.cc, while executing the method
  create_worker_threads, the held lock is not released correctly, which allows local users
  to trigger a denial of service due to the deadlock,

  - CVE-2022-31623: In extra/mariabackup/ds_compress.cc, while executing the method
  create_worker_threads, the held lock thd->ctrl_mutex is not released correctly, which allows
  local users to trigger a denial of service due to the deadlock.");

  # TODO: Re-check the versions once the CVE is listed on https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb
  script_tag(name:"affected", value:"MariaDB versions prior to 10.2.42, 10.3.x prior to 10.3.33,
  10.4.x prior to 10.4.23, 10.5.x prior to 10.5.14, 10.6.x prior to 10.6.6 and 10.7.x prior to
  10.7.2.");

  script_tag(name:"solution", value:"Update to version 10.2.42, 10.3.33, 10.4.23, 10.5.14, 10.6.6,
  10.7.2 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26561");
  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/e1eb39a446c30b8459c39fd7f2ee1c55a36e97d2");
  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/7c30bc38a588b22b01f11130cfe99e7f36accf94");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.2.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.42");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.3.0", test_version_up: "10.3.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.33");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.4.0", test_version_up: "10.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.23");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.5.0", test_version_up: "10.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.6.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.7.0", test_version_up: "10.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
