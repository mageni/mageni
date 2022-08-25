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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104301");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-19 11:57:08 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-28757");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client 5.7.3 < 5.11.6 Privilege Escalation Vulnerability (ZSB-22019) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl");
  script_mandatory_keys("zoom/client/mac/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Zoom Client for Meetings for macOS contains a vulnerability
  in the auto update process.");

  script_tag(name:"impact", value:"A local low-privileged user could exploit this vulnerability to
  escalate their privileges to root.

  Note: This issue allows for a bypass of the patch issued in 5.11.5 to address CVE-2022-28756.");

  script_tag(name:"affected", value:"Zoom Client versions starting from 5.7.3 and prior to
  5.11.6.");

  script_tag(name:"solution", value:"Update to version 5.11.6 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.7.3", test_version_up: "5.11.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.11.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
