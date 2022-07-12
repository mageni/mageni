##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsb16-25_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Adobe Flash Player Security Updates( apsb16-25 )-Windows
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808578");
  script_version("$Revision: 11969 $");
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
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-13 08:55:43 +0530 (Wed, 13 Jul 2016)");
  script_name("Adobe Flash Player Security Updates( apsb16-25 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - A race condition vulnerability.

  - A type confusion vulnerabilities.

  - An use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - A memory corruption vulnerabilities.

  - A stack corruption vulnerabilities.

  - A security bypass vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers lead to information disclosure,
  and code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.366 and 21.x before 22.0.0.209 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.366, or 22.0.0.209, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html");

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

if(version_in_range(version:playerVer, test_version:"21", test_version2:"22.0.0.208"))
{
  fix = "22.0.0.209";
  VULN = TRUE;
}

else if(version_is_less(version:playerVer, test_version:"18.0.0.366"))
{
  fix = "18.0.0.366";
  VULN = TRUE;
}

if(VULN)
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

