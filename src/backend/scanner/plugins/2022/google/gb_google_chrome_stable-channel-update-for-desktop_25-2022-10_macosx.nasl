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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826609");
  script_version("2022-10-31T10:12:00+0000");
  script_cve_id("CVE-2022-3652", "CVE-2022-3653", "CVE-2022-3654", "CVE-2022-3655",
                "CVE-2022-3656", "CVE-2022-3657", "CVE-2022-3658", "CVE-2022-3659",
                "CVE-2022-3660", "CVE-2022-3661");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-10-31 10:12:00 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-28 13:36:58 +0530 (Fri, 28 Oct 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_25-2022-10) - MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Type Confusion in V8.

  - Heap buffer overflow in Vulkan.

  - Use after free in Layout.

  - Heap buffer overflow in Media Galleries.

  - Insufficient data validation in File System.

  - Use after free in Extensions.

  - Use after free in Feedback service on Chrome OS.

  - Use after free in Accessibility.

  - Inappropriate implementation in Full screen mode.

  - Insufficient data validation in Extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and corrupt memory on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  107.0.5304.62 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  107.0.5304.62 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"107.0.5304.62"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"107.0.5304.62", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
