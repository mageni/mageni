###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_feb16_windows.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Adobe Flash Player Multiple Vulnerabilities -01 Feb16 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806865");
  script_version("$Revision: 12313 $");
  script_cve_id("CVE-2016-0964", "CVE-2016-0965", "CVE-2016-0966", "CVE-2016-0967",
                "CVE-2016-0968", "CVE-2016-0969", "CVE-2016-0970", "CVE-2016-0971",
                "CVE-2016-0972", "CVE-2016-0973", "CVE-2016-0974", "CVE-2016-0975",
                "CVE-2016-0976", "CVE-2016-0977", "CVE-2016-0978", "CVE-2016-0979",
                "CVE-2016-0980", "CVE-2016-0981", "CVE-2016-0982", "CVE-2016-0983",
                "CVE-2016-0984", "CVE-2016-0985");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-10 13:23:06 +0530 (Wed, 10 Feb 2016)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 Feb16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption vulnerabilities

  - Multiple use-after-free vulnerabilities

  - A heap buffer overflow vulnerability

  - A type confusion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will
  potentially allow an attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.329 and 19.x and 20.x before 20.0.0.306 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.329 or 20.0.0.306 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-04.html");

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

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"20.0.0.305"))
{
  fix = "20.0.0.306";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.329"))
{
  fix = "18.0.0.329";
  VULN = TRUE;
}

if(VULN)
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
