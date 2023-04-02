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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126398");
  script_version("2023-03-22T10:08:37+0000");
  script_tag(name:"last_modification", value:"2023-03-22 10:08:37 +0000 (Wed, 22 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-17 10:34:16 +0000 (Fri, 17 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2023-22883");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.13.5 Local Privilege Escalation Vulnerability (ZSB-23003) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"The Zoom Client for Meetings for Windows installer is prone to
  a local privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A local low-privileged user could exploit this vulnerability in
  an attack chain during the installation process to escalate their privileges to the SYSTEM
  user");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.13.5.");

  script_tag(name:"solution", value:"Update to version 5.13.5 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.13.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.13.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

