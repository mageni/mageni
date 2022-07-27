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
  script_oid("1.3.6.1.4.1.25623.1.0.126022");
  script_version("2022-06-23T12:49:37+0000");
  script_tag(name:"last_modification", value:"2022-06-23 12:49:37 +0000 (Thu, 23 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-04-13 07:06:23 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 16:37:00 +0000 (Thu, 21 Apr 2022)");

  script_cve_id("CVE-2022-27444", "CVE-2022-27445", "CVE-2022-27446", "CVE-2022-27447",
                "CVE-2022-27448", "CVE-2022-27449", "CVE-2022-27451", "CVE-2022-27452",
                "CVE-2022-27555", "CVE-2022-27456", "CVE-2022-27457", "CVE-2022-27458");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB Multiple Vulnerabilities (April 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-27444: Segmentation fault via the component sql/item_subselect.cc

  - CVE-2022-27445: DoS due segmentation fault via component sql/sql_window.cc

  - CVE-2022-27446: Segmentation fault via the component sql/item_cmpfunc.h

  - CVE-2022-27447: Use-after-free in the component Binary_string::free_buffer() at
  /sql/sql_string.h

  - CVE-2022-27448: Assertion failure via 'node->pcur->rel_pos == BTR_PCUR_ON' at /row/row0mysql.cc

  - CVE-2022-27449: DoS due segmentation fault via component sql/item_func.cc:148

  - CVE-2022-27451: Segmentation fault via the component sql/field_conv.cc

  - CVE-2022-27452: DoS due segmentation fault via component sql/item_cmpfunc.cc.

  - CVE-2022-27455: Use-after-free in the component my_wildcmp_8bit_impl at /strings/ctype-simple.c

  - CVE-2022-27456: Wrong use of dynamic memory during program operation

  - CVE-2022-27457: Use-after-free in the component my_mb_wc_latin1 at /strings/ctype-latin1.c

  - CVE-2022-27458: Use-after-free in the component Binary_string::free_buffer() at
  /sql/sql_string.h");

  script_tag(name:"affected", value:"MariaDB version 10.4.x through 10.4.24, 10.5.x through
  10.5.15, 10.6.x through 10.6.7 and 10.7.x through 10.7.3.");

  script_tag(name:"solution", value:"Update to version 10.4.25, 10.5.16, 10.6.8, 10.7.4 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28080");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28081");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28082");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28099");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28095");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28089");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28094");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28090");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28097");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28093");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-28099");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.25");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.6.0", test_version2: "10.6.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.8");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.7.0", test_version2: "10.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
