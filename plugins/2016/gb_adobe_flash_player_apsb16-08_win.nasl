##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsb16-08_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Adobe Flash Player Security Updates-APSB16-08 (Windows)
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807606");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-0960", "CVE-2016-0961", "CVE-2016-0962", "CVE-2016-0963",
		"CVE-2016-0986", "CVE-2016-0987", "CVE-2016-0988", "CVE-2016-0989",
		"CVE-2016-0990", "CVE-2016-0991", "CVE-2016-0992", "CVE-2016-0993",
		"CVE-2016-0994", "CVE-2016-0995", "CVE-2016-0996", "CVE-2016-0997",
		"CVE-2016-0998", "CVE-2016-0999", "CVE-2016-1000", "CVE-2016-1001",
		"CVE-2016-1002", "CVE-2016-1005", "CVE-2016-1010");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-11 13:50:43 +0530 (Fri, 11 Mar 2016)");
  script_name("Adobe Flash Player Security Updates-APSB16-08 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - An integer overflow vulnerabilities.

  - Ause-after-free vulnerabilities.

  - A heap overflow vulnerability.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.333 and 19.x and 20.x before 21.0.0.182 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.333, or 21.0.0.182, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"21.0.0.181"))
{
  fix = "21.0.0.182";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.333"))
{
  fix = "18.0.0.333";
  VULN = TRUE;
}

if(VULN)
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

