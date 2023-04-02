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
  script_oid("1.3.6.1.4.1.25623.1.0.126397");
  script_version("2023-03-22T10:08:37+0000");
  script_tag(name:"last_modification", value:"2023-03-22 10:08:37 +0000 (Wed, 22 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-17 10:34:16 +0000 (Fri, 17 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2023-22881", "CVE-2023-22882", "CVE-2023-28597");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.13.5 Multiple Vulnerabilities (ZSB-23002, ZSB-23005) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/lin/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-22881: A malicious actor could send specially crafted UDP traffic to a victim Zoom
  client to remotely cause the client to crash, causing a denial of service.

  - CVE-2023-22882: A malicious actor could send specially crafted UDP traffic to a victim Zoom
  client to remotely cause the client to crash, causing a denial of service.

  - CVE-2023-28597: If a victim saves a local recording to an SMB location and later opens it using
  a link from Zooms web portal, an attacker positioned on an adjacent network to the victim client
  could set up a malicious SMB server to respond to client requests, causing the client to execute
  attacker controlled executables."); #Note: cve description is duplicated on zoom and NVD adviosry also

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
