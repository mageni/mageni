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
  script_oid("1.3.6.1.4.1.25623.1.0.814885");
  script_version("2019-04-30T06:40:08+0000");
  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808",
                "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5812",
                "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5816",
                "CVE-2019-5817", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820",
                "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-30 06:40:08 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-26 13:07:09 +0530 (Fri, 26 Apr 2019)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_23-2019-04)-Windows");

  script_tag(name:"summary", value:"This host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free errors in PDFium and Blink

  - An integer overflow error in Angle.

  - A memory corruption issue in V8.

  - A user information disclosure in Autofill.

  - Multiple CORS bypass errors in Blink and download manager.

  - A URL spoof error in Omnibox on iOS.

  - An out of bounds read error in V8.

  - Heap buffer overflow errors in Blink and Angle on Windows.

  - An uninitialized value error in media reader.

  - A forced navigation error from service worker.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the browser, gain access to sensitive
  information, bypass security restrictions and perform unauthorized actions, or
  cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 74.0.3729.108 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 74.0.3729.108
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/04/stable-channel-update-for-desktop_23.html");
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

if(version_is_less(version:chr_ver, test_version:"74.0.3729.108"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"74.0.3729.108", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
