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
  script_oid("1.3.6.1.4.1.25623.1.0.815201");
  script_version("2019-06-06T13:02:35+0000");
  script_cve_id("CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831",
                "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835",
                "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839",
                "CVE-2019-5840");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-06-06 13:02:35 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-06 10:58:30 +0530 (Thu, 06 Jun 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-06)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A use after free error in ServiceWorker.

  - A use after free error in Download Manager.

  - An incorrectly credentialed requests issue in CORS.

  - An incorrect map processing issue in V8.

  - An incorrect CORS handling issue in XHR.

  - An inconsistent security UI placement issue.

  - A URL spoof error in Omnibox.

  - An out of bounds read error in Swiftshader.

  - A heap buffer overflow error in Angle.

  - A cross-origin resources size disclosure in Appcache.

  - An overly permissive tab access in Extensions.

  - An incorrect handling of certain code points in Blink.

  - A popup blocker bypass issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the browser, obtain sensitive
  information, conduct spoofing attacks, bypass security restrictions, and
  perform unauthorized actions, or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 75.0.3770.80 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  75.0.3770.80 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://www.google.com/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"75.0.3770.80"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"75.0.3770.80", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
