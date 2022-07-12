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
  script_oid("1.3.6.1.4.1.25623.1.0.147987");
  script_version("2022-04-13T07:17:20+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-13 07:06:23 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-27376", "CVE-2022-27377", "CVE-2022-27378", "CVE-2022-27379",
                "CVE-2022-27380", "CVE-2022-27381", "CVE-2022-27382", "CVE-2022-27383",
                "CVE-2022-27384", "CVE-2022-27385", "CVE-2022-27386", "CVE-2022-27387");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("MariaDB Multiple Vulnerabilities (April 2022) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MariaDB version 10.9.x and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 13th April, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26354");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26281");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26423");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26353");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26280");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26061");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26402");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26323");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26047");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26415");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26406");
  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-26422");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
