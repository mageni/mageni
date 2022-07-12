##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop-2017-04_lin.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-04)-Linux
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810754");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-5057", "CVE-2017-5058", "CVE-2017-5059", "CVE-2017-5060",
"CVE-2017-5061", "CVE-2017-5062", "CVE-2017-5063", "CVE-2017-5064",
"CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067", "CVE-2017-5069");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 11:29:33 +0530 (Thu, 20 Apr 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-04)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - The type confusion in PDFium.

  - The heap use after free in Print Preview.

  - The type confusion in Blink.

  - The URL spoofing in Omnibox.

  - An use after free in Chrome Apps.

  - The heap overflow in Skia.

  - An use after free in Blink.

  - An incorrect UI in Blink.

  - An incorrect signature handing in Networking.

  - The cross-origin bypass in Blink.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attacker to bypass security, execute
  arbitrary code, cause denial of service and conduct spoofing attacks.");

  script_tag(name:"affected", value:"Google Chrome version prior to 58.0.3029.81 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 58.0.3029.81 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/04/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"58.0.3029.81"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"58.0.3029.81");
  security_message(data:report);
  exit(0);
}
