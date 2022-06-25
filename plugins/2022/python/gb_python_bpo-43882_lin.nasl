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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147630");
  script_version("2022-02-14T05:49:51+0000");
  script_tag(name:"last_modification", value:"2022-02-14 11:09:18 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-14 05:34:48 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-0391");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python urllib.parse Vulnerability (bpo-43882) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a vulnerability urllib.parse.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Python, specifically within the
  urllib.parse module. This module helps break Uniform Resource Locator (URL) strings into
  components. The issue involves how the urlparse method does not sanitize input and allows
  characters like '\r' and '\n' in the URL path. This flaw allows an attacker to input a crafted
  URL, leading to injection attacks.");

  script_tag(name:"affected", value:"Python prior to version 3.6.14, version 3.7.x through 3.7.10,
  3.8.x through 3.8.10 and 3.9.x through 3.9.4.");

  script_tag(name:"solution", value:"Update to version 3.6.14, 3.7.11, 3.8.11, 3.9.5 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/urllib_parse_newline_tabs.html");
  script_xref(name:"Advisory-ID", value:"bpo-43882");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.7.0", test_version_up: "3.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
