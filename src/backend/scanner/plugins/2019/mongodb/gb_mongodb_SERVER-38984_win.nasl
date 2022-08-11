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
  script_oid("1.3.6.1.4.1.25623.1.0.142724");
  script_version("2019-08-12T01:24:03+0000");
  script_tag(name:"last_modification", value:"2019-08-12 01:24:03 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-09 08:13:39 +0000 (Fri, 09 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-2386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB 3.4 < 3.4.22, 3.6 < 3.6.13, 4.0 < 4.0.9, 4.1 < 4.1.9 User Session Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mongodb/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MongoDB is prone to a vulnerability where after user deletion the improper
  invalidation of authorization sessions allows an authenticated user's session to persist and become conflated
  with new accounts, if those accounts reuse the names of deleted ones.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MongoDB versions 3.4 prior to 3.4.22, 3.6 prior to 3.6.13, 4.0 prior to
  4.0.9 and 4.1 prior to 4.1.9.");

  script_tag(name:"solution", value:"Update to version 3.4.22, 3.6.13, 4.0.9, 4.1.9 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-38984");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0829");

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

if (version_in_range(version: version, test_version: "3.6", test_version2: "3.6.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.13");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
