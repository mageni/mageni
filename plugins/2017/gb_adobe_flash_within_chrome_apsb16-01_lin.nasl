##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_within_chrome_apsb16-01_lin.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Adobe Flash Player Within Google Chrome Security Update (apsb16-01)-Linux
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811496");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2015-8459", "CVE-2015-8460", "CVE-2015-8634", "CVE-2015-8635",
                "CVE-2015-8636", "CVE-2015-8638", "CVE-2015-8639", "CVE-2015-8640",
                "CVE-2015-8641", "CVE-2015-8642", "CVE-2015-8643", "CVE-2015-8644",
                "CVE-2015-8645", "CVE-2015-8646", "CVE-2015-8647", "CVE-2015-8648",
                "CVE-2015-8649", "CVE-2015-8650", "CVE-2015-8651", "CVE-2016-0959");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-18 15:29:26 +0530 (Tue, 18 Jul 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (apsb16-01)-Linux");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A type confusion vulnerability.

  - An integer overflow vulnerability.

  - Multiple use-after-free vulnerabilities.

  - Multiple memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers execute remote code and can get
  sensitive information which can lead to denial of service.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  20.0.0.267 within Google Chrome on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for
  Google Chrome 20.0.0.267, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Lin/Ver");

  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"20.0.0.267"))
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:"20.0.0.267");
  security_message(data:report);
  exit(0);
}
exit(0);
