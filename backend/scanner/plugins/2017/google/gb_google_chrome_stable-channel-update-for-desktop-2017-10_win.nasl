##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop-2017-10_win.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-10)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811872");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127",
                "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5132", "CVE-2017-5130",
                "CVE-2017-5131", "CVE-2017-5133", "CVE-2017-15386", "CVE-2017-15387",
                "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391",
                "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395");
  script_bugtraq_id(101482);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-19 12:40:22 +0530 (Thu, 19 Oct 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-10)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An input validation error in MHTML.

  - Multiple heap overflow errors in Skia, WebGL and libxml2.

  - Multiple use after free errors in PDFium and WebAudio.

  - An incorrect stack manipulation in WebAssembly.

  - Multiple Out of bounds read and write errors in Skia.

  - UI spoofing in Blink.

  - Content security bypass.

  - Multiple URL spoofing errors in OmniBox.

  - An extension limitation bypass in Extensions.

  - An incorrect registry key handling in PlatformIntegration.

  - Referrer leak in Devtools.

  - URL spoofing in extensions UI.

  - Null pointer dereference error in ImageCapture.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary script,
  conduct spoofing attack, corrupt memory, bypass security and cause
  denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  62.0.3202.62 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  62.0.3202.62 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/10/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"62.0.3202.62"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"62.0.3202.62");
  security_message(data:report);
  exit(0);
}
