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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118244");
  script_version("2021-10-04T14:56:34+0000");
  script_tag(name:"last_modification", value:"2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-04 12:04:36 +0200 (Mon, 04 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)");

  script_cve_id("CVE-2018-1060", "CVE-2018-1061");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.15, 3.x < 3.4.9, 3.5.x < 3.5.6, 3.6.x < 3.6.5, 3.7.x < 3.7.0.beta3 Python Issue (Issue32981) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Python is failing to sanitize against backtracking in:

  - CVE-2018-1060: pop3lib's apop method

  - CVE-2018-1061: 'difflib.IS_LINE_JUNK' method");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to conduct
  a denial of service attack on the affected user.");

  script_tag(name:"affected", value:"Python before versions 2.7.15, 3.4.9, 3.5.6, 3.6.5
  and 3.7.0.beta3.");

  script_tag(name:"solution", value:"Update to version 2.7.15, 3.4.9, 3.5.6, 3.6.5,
  3.7.0.beta3 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue32981");
  script_xref(name:"Advisory-ID", value:"Issue32981");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.7.15")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.7.15", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.0", test_version2:"3.4.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.4.9", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.5", test_version2:"3.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.5.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"3.6", test_version2:"3.6.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.6.5", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
