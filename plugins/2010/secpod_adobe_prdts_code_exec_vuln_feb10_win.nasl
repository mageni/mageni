###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_code_exec_vuln_feb10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902128");
  script_version("$Revision: 12653 $");
  script_cve_id("CVE-2010-0188", "CVE-2010-0186");
  script_bugtraq_id(38195, 38198);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_name("Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to remote code
execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is caused by a memory corruption error in the 'authplay.dll' module
when processing malformed Flash data within a PDF document and some unspecified
error.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code by tricking
a user into opening a PDF file embedding a malicious Flash animation and bypass
intended sandbox restrictions allowing cross-domain requests.");
  script_tag(name:"affected", value:"Adobe Reader version 8.x before 8.2.1 and 9.x before 9.3.1

  Adobe Acrobat version 8.x before 8.2.1 and 9.x before 9.3.1");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.3.1 or 8.2.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56297");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0399");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023601.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:readerVer, test_version:"8.2.1") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:acrobatVer, test_version:"8.2.1") ||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.3.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
