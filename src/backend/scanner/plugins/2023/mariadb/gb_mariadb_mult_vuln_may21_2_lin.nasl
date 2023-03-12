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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149349");
  script_version("2023-02-28T10:08:51+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:08:51 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-22 04:17:22 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");

  script_cve_id("CVE-2021-2166", "CVE-2021-2154", "CVE-2021-2180", "CVE-2022-21451");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB < 10.2.38 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-2166: Denial of service (DoS) in MySQL

  - CVE-2021-2154: Denial of service (DoS) in MySQL

  - CVE-2021-2180: Denial of service (DoS) in MySQL

  - CVE-2022-21451: Denial of service (DoS) in MySQL");

  script_tag(name:"affected", value:"MariaDB prior to version 10.2.38.");

  script_tag(name:"solution", value:"Update to version 10.2.38 or later.");

  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10238-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.2.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.38");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
