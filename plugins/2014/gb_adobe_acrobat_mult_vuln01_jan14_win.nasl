###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_jan14_win.nasl 34613 2014-01-21 12:51:13Z Jan$
#
# Adobe Acrobat Multiple Vulnerabilities - 01 Jan14 (Windows)
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804070");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0493", "CVE-2014-0495", "CVE-2014-0496");
  script_bugtraq_id(64802, 64803, 64804);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 12:51:13 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Acrobat Multiple Vulnerabilities - 01 Jan14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat and is prone to multiple unspecified
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to some unspecified errors and an error in dereferencing already
freed memory.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, execute arbitrary code and
compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Acrobat X Version 10.x prior to 10.1.9 on Windows
Adobe Acrobat XI Version 11.x prior to 11.0.06 on Windows");
  script_tag(name:"solution", value:"Update to Adobe Acrobat Version 10.1.9 or 11.0.06 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56303");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/acrobat/apsb14-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!acrobatVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(acrobatVer && acrobatVer =~ "^10|11")
{
  if((version_in_range(version:acrobatVer, test_version:"10.0", test_version2: "10.1.8"))||
     (version_in_range(version:acrobatVer, test_version:"11.0", test_version2: "11.0.05")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
