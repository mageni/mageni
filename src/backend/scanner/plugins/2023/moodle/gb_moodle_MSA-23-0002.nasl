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
  script_oid("1.3.6.1.4.1.25623.1.0.124262");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-01-26 10:40:17 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2023-23922");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle 4.0.x < 4.0.6, 4.1.x < 4.1.1 XSS Vulnerability (MSA-23-0002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Reflected XSS risk in blog search.");

  script_tag(name:"affected", value:"Moodle versions 4.0 prior to 4.0.6 and 4.1
  prior to 4.1.1.");

  script_tag(name:"solution", value:"Update to version 4.0.6, 4.1.1 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=443273");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1", test_version_up: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
