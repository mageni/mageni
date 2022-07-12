###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln01_feb13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803415");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_bugtraq_id(57931, 57947);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-19 18:24:49 +0530 (Tue, 19 Feb 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code or cause
a denial of service via a crafted PDF document.");
  script_tag(name:"affected", value:"Adobe Reader Version 9.x prior to 9.5.4 on Windows

Adobe Reader X Version 10.x prior to 10.1.6 on Windows

Adobe Reader XI Version 11.x prior to 11.0.02 on Windows");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5.4, 10.1.6, 11.0.02 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52196");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^(9|10|11)")
{
  if((version_in_range(version:readerVer, test_version:"9.0", test_version2: "9.5.3"))||
     (version_in_range(version:readerVer, test_version:"10.0", test_version2: "10.1.5"))||
     (version_in_range(version:readerVer, test_version:"11.0", test_version2: "11.0.01")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
