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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146380");
  script_version("2021-07-26T05:10:58+0000");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-26 05:01:41 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-20333");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MongoDB Log Spoofing Vulnerability (SERVER-50605)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_mongodb_detect.nasl");
  script_mandatory_keys("mongodb/installed");

  script_tag(name:"summary", value:"MongoDB is prone to a log spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sending specially crafted commands to a MongoDB Server may result
  in artificial log entries being generated or for log entries to be split.");

  script_tag(name:"affected", value:"MongoDB version 3.6.x through 3.6.20, 4.0.x through 4.0.21 and
  4.2.x through 4.2.10.");

  script_tag(name:"solution", value:"Update to version 3.6.21, 4.0.22, 4.2.11 or later.");

  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-50605");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.6.0", test_version2: "3.6.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.21");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.22");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
