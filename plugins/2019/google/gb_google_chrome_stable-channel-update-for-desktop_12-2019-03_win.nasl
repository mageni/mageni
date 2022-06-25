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
  script_oid("1.3.6.1.4.1.25623.1.0.814870");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790",
                "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794",
                "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798",
                "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802",
                "CVE-2019-5803", "CVE-2019-5804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-14 12:16:02 +0530 (Thu, 14 Mar 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_12-2019-03)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free errors in Canvas, FileAPI, WebMIDI.

  - Heap buffer overflow error in V8.

  - Type confusion error in V8.

  - Integer overflow error in PDFium.

  - Excessive permissions for private API in Extensions.

  - Security UI spoofing.

  - Race condition in Extensions and DOMStorage.

  - Out of bounds read error in Skia.

  - CSP bypass errors with blob URL and Javascript URLs'.

  - Incorrect Omnibox display on iOS.

  - Command line command injection on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary code, cause denial of service and spoofing attacks,
  and also take control of an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 73.0.3683.75 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 73.0.3683.75 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/03/stable-channel-update-for-desktop_12.html");
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

if(version_is_less(version:chr_ver, test_version:"73.0.3683.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"73.0.3683.75", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
