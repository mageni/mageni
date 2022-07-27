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
  script_oid("1.3.6.1.4.1.25623.1.0.820016");
  script_version("2022-03-10T05:08:03+0000");
  script_cve_id("CVE-2022-0789", "CVE-2022-0790", "CVE-2022-0791", "CVE-2022-0792",
                "CVE-2022-0793", "CVE-2022-0794", "CVE-2022-0795", "CVE-2022-0796",
                "CVE-2022-0797", "CVE-2022-0798", "CVE-2022-0799", "CVE-2022-0800",
                "CVE-2022-0801", "CVE-2022-0802", "CVE-2022-0803", "CVE-2022-0804",
                "CVE-2022-0805", "CVE-2022-0806", "CVE-2022-0807", "CVE-2022-0808",
                "CVE-2022-0809");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-03-10 11:17:35 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-03 11:50:34 +0530 (Thu, 03 Mar 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop-2022-03) - MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Heap buffer overflow errors in ANGLE, Cast UI.

  - Use after free errors in Cast UI, Omnibox, Views, WebShare, Media, MediaStream,
    Browser Switcher and Chrome OS Shell.

  - Inappropriate implementation in Full screen mode, HTML parser, Permissions,
    Autofill.

  - Out of bounds memory access errors in WebXR, Mojo.

  - Out of bounds read in ANGLE.

  - Data leak in Canvas.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and leak sensitive information.");

  script_tag(name:"affected", value:"Google Chrome version prior to 99.0.4844.51
  on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 99.0.4844.51
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop.html");
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

if(version_is_less(version:vers, test_version:"99.0.4844.51"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"99.0.4844.51", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
