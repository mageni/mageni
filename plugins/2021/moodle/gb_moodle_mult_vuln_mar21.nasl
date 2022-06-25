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
  script_oid("1.3.6.1.4.1.25623.1.0.112874");
  script_version("2021-03-17T09:04:49+0000");
  script_tag(name:"last_modification", value:"2021-03-17 11:26:15 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-17 08:58:11 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-11022", "CVE-2020-11023", "CVE-2021-20279", "CVE-2021-20280",
                "CVE-2021-20281", "CVE-2021-20282", "CVE-2021-20283");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.5.17, 3.8.x < 3.8.8, 3.9.x < 3.9.5, 3.10.x < 3.10.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2020-11022 and CVE-2020-11023: The JQuery version used by Moodle required
  upgrading to 3.5.1 to patch some published potential vulnerabilities.

  - CVE-2021-20279: Stored XSS via ID number user profile field

  - CVE-2021-20280: Stored XSS and blind SSRF possible via feedback answer text

  - CVE-2021-20281: User full name disclosure within online users block

  - CVE-2021-20282: Bypass email verification secret when confirming account registration

  - CVE-2021-20283: Fetching a user's enrolled courses via web services did not check profile access in each course.");

  script_tag(name:"affected", value:"Moodle version 3.5.16 and prior, 3.8 through 3.8.7, 3.9 through 3.9.4 and 3.10 through 30.1.");

  script_tag(name:"solution", value:"Update to version 3.5.17, 3.8.8, 3.9.5 or 3.10.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419650");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419651");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419652");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419653");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419654");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=419655");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "3.5.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.8.0", test_version2: "3.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.9.0", test_version2: "3.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.10.0", test_version2: "3.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
