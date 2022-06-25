##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsb17-10_lin.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Adobe Flash Player Security Updates( apsb17-10 )-Linux
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810840");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-3058", "CVE-2017-3059", "CVE-2017-3060", "CVE-2017-3061",
                "CVE-2017-3062", "CVE-2017-3063", "CVE-2017-3064", "CVE-2015-5122",
                "CVE-2015-5123");
  script_bugtraq_id(97551, 97557, 75712, 75710);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-12 08:48:07 +0530 (Wed, 12 Apr 2017)");
  script_name("Adobe Flash Player Security Updates( apsb17-10 )-Linux");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Use-after-free vulnerabilities that could lead to code execution.

  - Memory corruption vulnerabilities that could lead to code execution.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerabilities will allow remote attackers to execute arbitrary code on
  the target user's system and that could potentially allow an attacker to
  take control of the affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  25.0.0.148 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  25.0.0.148, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"25.0.0.148"))
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:"25.0.0.148");
  security_message(data:report);
  exit(0);
}
