# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112715");
  script_version("2020-03-23T11:09:56+0000");
  script_tag(name:"last_modification", value:"2020-03-23 11:09:56 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-23 11:00:00 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-10802", "CVE-2020-10803", "CVE-2020-10804");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.5, 5.x < 5.0.2 Multiple SQL Injection Vulnerabilities - PMASA-2020-2, PMSA-2020-3, PMSA-2020-4 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following SQL injection vulnerabilities exist:

  - An SQL injection vulnerability was found in how phpMyAdmin retrieves the current username

  - An SQL injection vulnerability has been discovered where certain parameters are not properly
  escaped when generating certain queries for search actions within phpMyAdmin

  - An SQL injection vulnerability was discovered where malicious code could be used to trigger
  an XSS attack through retrieving and displaying results.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - create a specially-crafted username and then trick the victim in to performing specific
  actions with that user account (such as editing its privileges)

  - generate specially-crafted database or table names

  - insert specially-crafted data in to certain database tables, which when retrieved
  (for instance, through the Browse tab) can trigger an XSS attack");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.5 and 5.x prior to 5.0.2.");

  script_tag(name:"solution", value:"Update to version 4.9.5, 5.0.2 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-2/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-4/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "4.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version =~ "^5\." && version_is_less(version: version, test_version: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
