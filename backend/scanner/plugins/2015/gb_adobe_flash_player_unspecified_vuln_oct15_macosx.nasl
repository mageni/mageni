###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_unspecified_vuln_oct15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Flash Player Unspecified Vulnerability Oct15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806099");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-7645", "CVE-2015-7647", "CVE-2015-7648");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 15:42:14 +0530 (Fri, 16 Oct 2015)");
  script_name("Adobe Flash Player Unspecified Vulnerability Oct15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified
  critical vulnerabilities in Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a crash and potentially an attacker to take control of the affected
  system.");

  script_tag(name:"affected", value:"Adobe Flash Player version 8.x through
  18.0.0.252, 19.x through 19.0.0.207 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  18.0.0.255 or 19.0.0.226 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsa15-05.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-27.html");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/new-adobe-flash-zero-day-used-in-pawn-storm-campaign");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/flashplayer");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:playerVer, test_version:"19.0", test_version2:"19.0.0.207"))
{
  fix = "19.0.0.226";
  VULN = TRUE;
}

else if(version_in_range(version:playerVer, test_version:"18.0", test_version2:"18.0.0.252"))
{
  fix = "18.0.0.255";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:' + fix + '\n';
  security_message(data:report);
  exit(0);
}
