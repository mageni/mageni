###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_sec_bypass_vuln_jan14_macosx.nasl 34612 2014-01-21 10:42:12Z Jan$
#
# Adobe Flash Player Security Bypass Vulnerability Jan14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804064");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_bugtraq_id(64807, 64810);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 10:42:12 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Flash Player Security Bypass Vulnerability Jan14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player and is prone to security bypass
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an unspecified error and other additional weakness.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, bypass certain security
restrictions and disclose certain memory information.");
  script_tag(name:"affected", value:"Adobe Flash Player before version 11.7.700.260, 11.8.x, 11.9.x before
12.0.0.38 on Mac OS X.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.260 or 12.0.0.38 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56267");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
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

if(version_is_less(version:playerVer, test_version:"11.7.700.260") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"12.0.0.37"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
