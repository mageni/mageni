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
  script_oid("1.3.6.1.4.1.25623.1.0.142533");
  script_version("2019-07-02T05:09:29+0000");
  script_tag(name:"last_modification", value:"2019-07-02 05:09:29 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-02 05:08:38 +0000 (Tue, 02 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-10164");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.9, 11.x < 11.4 Buffer Overflow Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a stack-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Any authenticated user can overflow a stack-based buffer by changing the user's
  own password to a purpose-crafted value. This often suffices to execute arbitrary code as the PostgreSQL
  operating system account.");

  script_tag(name:"affected", value:"PostgreSQL version 10.x prior to 10.9 and 11.x prior to 11.4.");

  script_tag(name:"solution", value:"Update to version 10.9, 11.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1949/");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
