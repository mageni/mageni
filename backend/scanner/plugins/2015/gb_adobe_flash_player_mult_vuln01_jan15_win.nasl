###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_jan15_win.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities-01 Jan15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805242");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-0301", "CVE-2015-0302", "CVE-2015-0303", "CVE-2015-0304",
                "CVE-2015-0305", "CVE-2015-0306", "CVE-2015-0307", "CVE-2015-0308",
                "CVE-2015-0309");
  script_bugtraq_id(72034, 72035, 72031, 72032, 72033, 72036, 72037, 72039, 72038);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-16 12:17:39 +0530 (Fri, 16 Jan 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Jan15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An unspecified error related to improper file validation.

  - Another unspecified error which can be exploited to capture keystrokes.

  - Two unspecified errors which can be exploited to corrupt memory.

  - Two unspecified errors which can be exploited to cause a heap-based
  buffer overflow.

  - A type confusion error which can be exploited to corrupt memory.

  - An out-of-bounds read error.

  - An unspecified use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to disclose potentially sensitive information and
  compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  13.0.0.260 and 14.x through 16.x before 16.0.0.257 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.260 or 16.0.0.257 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62177");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb15-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"13.0.0.260") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"16.0.0.256"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
