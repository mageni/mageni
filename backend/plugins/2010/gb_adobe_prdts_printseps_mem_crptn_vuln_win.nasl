###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_printseps_mem_crptn_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Acrobat and Reader 'printSeps()' Function Heap Corruption Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801545");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-4091");
  script_bugtraq_id(44638);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Acrobat and Reader 'printSeps()' Function Heap Corruption Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42095");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62996");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15419/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2890");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2010/11/potential-issue-in-adobe-reader.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to crash an affected application
  or compromise a vulnerable system by tricking a user into opening a specially
  crafted PDF file.");
  script_tag(name:"affected", value:"Adobe Reader version 8.x to 8.1.7 and 9.x before 9.4.1

  Adobe Acrobat version 8.x to 8.1.7 and 9.x before 9.4.1 on windows");
  script_tag(name:"insight", value:"This issue is caused by a heap corruption error in the 'EScript.api' plugin
  when processing the 'printSeps()' function within a PDF document.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.4.1 or later");
  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to heap
  corruption Vulnerability");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:readerVer, test_version:"8.1.7") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:acrobatVer, test_version:"8.1.7") ||
     version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.4.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
