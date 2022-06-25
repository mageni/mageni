############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_within_chrome_apsb16-25_macosx.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Adobe Flash Player Within Google Chrome Security Update (apsb16-25) - Mac OS X
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

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810648");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175",
                "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179",
                "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183",
                "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187",
                "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217",
                "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221",
                "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225",
                "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229",
                "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233",
                "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237",
                "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241",
                "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245",
                "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249",
                "CVE-2016-7020");
  script_bugtraq_id(94192, 91719, 91718, 91724, 91725, 91722, 91723, 91720, 91721);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-17 20:23:07 +0530 (Fri, 17 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (apsb16-25) - Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A race condition vulnerability.

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - Multiple memory corruption vulnerabilities.

  - Multiple stack corruption vulnerabilities.

  - A security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers lead to information disclosure and code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 22.0.0.209 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 22.0.0.209 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"22.0.0.209"))
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:"22.0.0.209");
  security_message(data:report);
  exit(0);
}