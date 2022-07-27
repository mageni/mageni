###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop_29-2018-05)-Windows
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813505");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6125", "CVE-2018-6126",
                "CVE-2018-6127", "CVE-2018-6128", "CVE-2018-6129", "CVE-2018-6130",
                "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134",
                "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138",
                "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142",
                "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-30 10:55:29 +0530 (Wed, 30 May 2018)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_29-2018-05)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An use after free in Blink.

  - Type confusion in Blink.

  - Overly permissive policy in WebUSB.

  - Heap buffer overflow in Skia.

  - Use after free in indexedDB.

  - uXSS in Chrome on iOS.

  - Out of bounds memory access in WebRTC, V8 and PDFium.

  - Incorrect mutability protection in WebAssembly.

  - Use of uninitialized memory in WebRTC.

  - URL spoof in Omnibox.

  - Referrer Policy bypass in Blink.

  - UI spoofing in Blink.

  - Leak of visited status of page in Blink.

  - Overly permissive policy in Extensions.

  - Restrictions bypass in the debugger extension API.

  - Incorrect escaping of MathML in Blink.

  - Password fields not taking advantage of OS protections in Views.");

  script_tag(name:"impact", value:"Successful exploitation can potentially
  result in the execution of arbitrary code or even enable full remote code
  execution capabilities and some unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to 67.0.3396.62
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  67.0.3396.62 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_58.html");
  script_xref(name:"URL", value:"https://www.google.co.in/chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"67.0.3396.62"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"67.0.3396.62", install_path:chr_path);
  security_message(data:report);
  exit(0);
}

exit(0);
