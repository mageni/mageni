###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_mult_vuln01_sep14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities-01 Sep14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804841");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0559", "CVE-2014-0557", "CVE-2014-0556", "CVE-2014-0555",
                "CVE-2014-0553", "CVE-2014-0552", "CVE-2014-0551", "CVE-2014-0550",
                "CVE-2014-0549", "CVE-2014-0548", "CVE-2014-0547", "CVE-2014-0554");
  script_bugtraq_id(69704, 69701, 69696, 69706, 69707, 69703, 69702, 69700,
                    69699, 69705, 69695, 69697);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-12 11:27:48 +0530 (Fri, 12 Sep 2014)");

  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Sep14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Flaws are due to multiple
  unspecified errors and an use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  13.0.0.244, 14.x and 15.x before 15.0.0.152 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.244 or 15.0.0.152 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60985");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:playerVer, test_version:"13.0.0.244") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"15.0.0.151"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
