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

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146192");
  script_version("2021-06-30T04:46:09+0000");
  script_tag(name:"last_modification", value:"2021-06-30 10:34:52 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-30 04:37:28 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-27577", "CVE-2021-32565", "CVE-2021-32566", "CVE-2021-32567", "CVE-2021-35474");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) 7.0.0 < 8.1.2, 9.0.0 < 9.0.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-27577: Incorrect handling of url fragment leads to cache poisoning

  - CVE-2021-32565: HTTP Request Smuggling, content length with invalid charters

  - CVE-2021-32566: Specific sequence of HTTP/2 frames can cause ATS to crash

  - CVE-2021-32567: Reading HTTP/2 frames too many times

  - CVE-2021-35474: Dynamic stack buffer overflow in cachekey plugin");

  script_tag(name:"affected", value:"Apache Traffic Server version 7.0.0 through 7.1.12, 8.0.0
  through 8.1.1 and 9.0.0 through 9.0.1.");

  script_tag(name:"solution", value:"Update to version 8.1.2, 9.0.2 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/ra1a41ff92a70d25bf576d7da2590575e8ff430393a3f4a0c34de4277%40%3Cusers.trafficserver.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.1.12") ||
    version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
