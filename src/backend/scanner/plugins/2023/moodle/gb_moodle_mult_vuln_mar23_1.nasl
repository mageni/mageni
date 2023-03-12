# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126375");
  script_version("2023-03-09T10:09:20+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:20 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-07 15:29:42 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-36392", "CVE-2021-36393", "CVE-2021-36394", "CVE-2021-36395",
                "CVE-2021-36396", "CVE-2021-36397", "CVE-2021-36400", "CVE-2021-36401",
                "CVE-2021-36402", "CVE-2021-36403");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.8, 3.10.x < 3.10.5, 3.11.x < 3.11.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-36392/MSA-21-0020: SQL injection risk in code fetching enrolled courses

  - CVE-2021-36393/MSA-21-0021: SQL injection risk in code fetching recent courses

  - CVE-2021-36394/MSA-21-0022: Remote code execution risk when Shibboleth authentication is
  enabled.

  - CVE-2021-36395/MSA-21-0023: Recursion denial of service possible due to recursive cURL in file
  repository

  - CVE-2021-36396/MSA-21-0024: Blind SSRF possible against cURL blocked hosts via redirect

  - CVE-2021-36397/MSA-21-0025: Messaging web service allows deletion of other users' messages.

  - CVE-2021-36400/MSA-21-0028: IDOR allows removal of other users' calendar URL subscriptions

  - CVE-2021-36401/MSA-21-0029: Stored XSS when exporting to data formats supporting HTML via user
  ID number.

  - CVE-2021-36402/MSA-21-0030: Insufficient escaping of users' names in account confirmation
  email.

  - CVE-2021-36403/MSA-21-0031: Messaging email notifications containing HTML may hide the final
  line of the email.");

  script_tag(name:"affected", value:"Moodle versions prior to 3.9.8, 3.10.x prior to 3.10.5 and
  3.11.x prior to 3.11.1.");

  script_tag(name:"solution", value:"Update to version 3.9.8, 3.10.5, 3.11.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424797");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424798");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424799");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424801");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424802");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424803");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424806");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424807");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424808");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=424809");

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

if (version_is_less(version: version, test_version: "3.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10", test_version_up: "3.10.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
