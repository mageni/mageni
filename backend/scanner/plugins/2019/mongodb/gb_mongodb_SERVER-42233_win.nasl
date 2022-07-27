# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142842");
  script_version("2019-09-03T08:37:44+0000");
  script_tag(name:"last_modification", value:"2019-09-03 08:37:44 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-03 08:27:20 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-2390");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB 3.4 < 3.4.22, 3.6 < 3.6.14, 4.0 < 4.0.11 Code Execution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"An unprivileged user or program on Microsoft Windows which can create OpenSSL
  configuration files in a fixed location may cause utility programs shipped with MongoDB server to run attacker
  defined code as the user running the utility.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MongoDB versions 3.4 prior to 3.4.22, 3.6 prior to 3.6.14 and 4.0 prior to
  4.0.11.");

  script_tag(name:"solution", value:"Update to version 3.4.22, 3.6.14, 4.0.11 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-42233");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port =  get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.4", test_version2: "3.4.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.22");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.14");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
