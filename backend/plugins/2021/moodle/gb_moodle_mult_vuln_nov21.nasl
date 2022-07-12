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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147204");
  script_version("2021-11-23T07:55:56+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-23 07:47:33 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-3943", "CVE-2021-43558", "CVE-2021-43559", "CVE-2021-43560");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.11, 3.10.x < 3.10.8, 3.11.x < 3.11.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - MSA-21-0038 / CVE-2021-3943: Remote code execution (RCE) risk when restoring malformed backup
  file

  - MSA-21-0039 / No CVE: The upstream Moodle machine learning backend and its reference in
  /lib/mlbackend/python/classes/processor.php were upgraded, which includes some security updates.

  - MSA-21-0040 / CVE-2021-43558: Reflected cross-site scripting (XSS) in filetype admin tool

  - MSA-21-0041 / CVE-2021-43559: Cross-site request forgery (CSRF) risk on delete related badge
  feature

  - MSA-21-0042 / CVE-2021-43560: IDOR in a calendar web service allows fetching of other users'
  action events");

  script_tag(name:"affected", value:"Moodle prior to version 3.9.11, version 3.10.x through 3.10.7
  and 3.11.x through 3.11.3.");

  script_tag(name:"solution", value:"Update to version 3.9.11, 3.10.8, 3.11.4 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=429095");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=429096");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=429097");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=429099");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=429100");

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

if (version_is_less(version: version, test_version: "3.9.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.10.0", test_version2: "3.10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.11.0", test_version2: "3.11.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
