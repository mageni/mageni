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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145603");
  script_version("2021-03-22T07:25:27+0000");
  script_tag(name:"last_modification", value:"2021-03-22 07:25:27 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-22 07:14:58 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2021-27928");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB RCE Vulnerability (MDEV-25179) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MariaDB is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An untrusted search path leads to eval injection, in which a database SUPER
  user can execute OS commands after modifying wsrep_provider and wsrep_notify_cmd.");

  script_tag(name:"affected", value:"MariaDB versions 10.2.x, 10.3.x, 10.4.x and 10.5.x.");

  script_tag(name:"solution", value:"Update to version 10.2.37, 10.3.28, 10.4.18, 10.5.9 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-25179");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "10.2.0", test_version2: "10.2.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.2.37");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.3.0", test_version2: "10.3.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.3.28");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.4.0", test_version2: "10.4.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.18");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
