# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815298");
  script_version("2019-09-16T07:48:47+0000");
  script_cve_id("CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5873",
                "CVE-2019-5874", "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877",
                "CVE-2019-5878", "CVE-2019-5879", "CVE-2019-5880", "CVE-2019-5881",
                "CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662",
                "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666",
                "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670",
                "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675",
                "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679",
                "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-09-16 07:48:47 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-13 11:41:12 +0530 (Fri, 13 Sep 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2019-09)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple use-after-free issues in media, Mojo, media and V8.

  - A heap overflow issue in Skia.

  - A use-after-free issue in Mojo.

  - A URL bar spoofing issue on iOS.

  - A issue where external URIs may trigger other browsers.

  - A URL bar spoof issue via download redirect.

  - An out-of-bounds access in V8.

  - An issue due to which extensions can read some local files.

  - A sameSite cookie bypass issue.

  - Arbitrary read in SwiftShader.

  - A URL spoof issue.

  - Full screen notification overlap and spoof issues.

  - For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, conduct spoofing attacks, cause denial of service and
  also take control of an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 77.0.3865.75 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  77.0.3865.75 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/09/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.google.com/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"77.0.3865.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"77.0.3865.75", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
