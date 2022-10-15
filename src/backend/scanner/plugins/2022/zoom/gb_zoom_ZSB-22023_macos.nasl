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
  script_oid("1.3.6.1.4.1.25623.1.0.127221");
  script_version("2022-10-13T13:59:50+0000");
  script_tag(name:"last_modification", value:"2022-10-13 13:59:50 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-13 12:43:10 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2022-28762");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client 5.10.6 < 5.12.0 Debbugging Port Misconfiguration Vulnerability (ZSB-22023) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl");
  script_mandatory_keys("zoom/client/mac/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to a debbugging port misconfiguration
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Debugging port misconfiguration in Zoom Apps in the Zoom Client for Meetings");

  script_tag(name:"impact", value:"A local malicious user could use this debugging port to connect
  to and control the Zoom Apps running in the Zoom client.");

  script_tag(name:"affected", value:"Zoom Client version 5.10.6 prior to 5.12.0.");

  script_tag(name:"solution", value:"Update to version 5.12.0 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.10.6", test_version_up: "5.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.12.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
