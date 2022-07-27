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

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.147108");
  script_version("2021-11-08T14:03:29+0000");
  script_tag(name:"last_modification", value:"2021-11-08 14:03:29 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-05 05:46:24 +0000 (Fri, 05 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-05 12:23:00 +0000 (Fri, 05 Nov 2021)");

  script_cve_id("CVE-2021-40848", "CVE-2021-40849", "CVE-2021-43264", "CVE-2021-43265",
                "CVE-2021-43266");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara < 20.04.5, 20.10.x < 20.10.3, 21.4.x < 21.04.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-40848: Exported CSV files could contain characters that a spreadsheet program could
  interpret as a command, leading to execution of a malicious string locally on a device, aka CSV
  injection.

  - CVE-2021-40849: The account associated with a web services token is vulnerable to being
  exploited and logged into, resulting in information disclosure (at a minimum) and often
  escalation of privileges.

  - CVE-2021-43264: Adjusting the path component for the page help file allows attackers to bypass
  the intended access control for HTML files via directory traversal. It replaces the - character
  with the / character.

  - CVE-2021-43265: Certain tag syntax could be used for XSS, such as via a SCRIPT element.

  - CVE-2021-43266: Exporting collections via PDF export could lead to code execution via shell
  metacharacters in a collection name.");

  script_tag(name:"affected", value:"Mahara prior to version 20.04.5, 20.10.x through 20.10.2 and
  21.04.x through 21.04.1.");

  script_tag(name:"solution", value:"Update to version 20.04.5, 20.10.3, 21.04.2 or later.");

  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1930471");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1930469");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1944979");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1944633");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/mahara/+bug/1942903");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "20.04.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.04.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.10.0", test_version2: "20.10.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.10.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.04.0", test_version2: "21.04.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.04.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
