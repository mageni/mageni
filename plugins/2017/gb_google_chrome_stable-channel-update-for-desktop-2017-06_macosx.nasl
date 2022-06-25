##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop-2017-06_macosx.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-06)-MAC OS X
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811082");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-5070", "CVE-2017-5071", "CVE-2017-5072", "CVE-2017-5073",
                "CVE-2017-5074", "CVE-2017-5075", "CVE-2017-5086", "CVE-2017-5076",
                "CVE-2017-5077", "CVE-2017-5078", "CVE-2017-5079", "CVE-2017-5080",
                "CVE-2017-5081", "CVE-2017-5082", "CVE-2017-5083", "CVE-2017-5085");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-06 10:00:35 +0530 (Tue, 06 Jun 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-06)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A type confusion in V8.

  - An out of bounds read error in V8.

  - Address spoofing in Omnibox.

  - Use after free error in print preview.

  - Use after free error in Apps Bluetooth.

  - Information leak in CSP reporting.

  - Heap buffer overflow in Skia.

  - Possible command injection in mailto handling.

  - UI spoofing in Blink.

  - Use after free error in credit card autofill.

  - Extension verification bypass.

  - Insufficient hardening in credit card editor.

  - Inappropriate javascript execution on WebUI pages.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to have some unspecified impact on the affected user.");

  script_tag(name:"affected", value:"Google Chrome version prior to 59.0.3071.86
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 59.0.3071.86
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"59.0.3071.86"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"59.0.3071.86");
  security_message(data:report);
  exit(0);
}
