###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_aug14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe AIR Multiple Vulnerabilities-01 Aug14 (Mac OS X)
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

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804746");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0538", "CVE-2014-0540", "CVE-2014-0541", "CVE-2014-0542",
                "CVE-2014-0543", "CVE-2014-0544", "CVE-2014-0545", "CVE-2014-5333");
  script_bugtraq_id(69192, 69190, 69191, 69194, 69195, 69196, 69197, 69320);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-19 15:11:46 +0530 (Tue, 19 Aug 2014)");
  script_name("Adobe AIR Multiple Vulnerabilities-01 Aug14 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Air and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple Flaws are due to an unspecified error and an use-after-free error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.");
  script_tag(name:"affected", value:"Adobe AIR before version 14.0.0.178 on Mac OS X.");
  script_tag(name:"solution", value:"Update to Adobe AIR version 14.0.0.178 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58593");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!airVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:airVer, test_version:"14.0.0.178"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
