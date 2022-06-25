###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_cooltype_mem_crptn_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801933");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-0610");
  script_bugtraq_id(47531);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_name("Adobe Reader and Acrobat 'CoolType.dll' Memory Corruption Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to memory
corruption and reemote code execution vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This issue is caused by a memory corruption error in the 'CoolType' library
when processing the malformed Flash content within a PDF document.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to crash an affected application
or compromise a vulnerable system by tricking a user into opening a specially
crafted PDF file.");
  script_tag(name:"affected", value:"Adobe Reader version prior to 9.4.4 and 10.x to 10.0.1

Adobe Acrobat version prior to 9.4.4 and 10.x to 10.0.2 on windows");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.4.4 or Acrobat 9.4.4 or 10.0.3  *****
  NOTE : No fix available for Adobe Reader X (10.x), vendors are planning to
         address this issue in next quarterly security update for Adobe Reader.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0923");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less(version:readerVer, test_version:"9.4.4") ||
    version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_less(version:acrobatVer, test_version:"9.4.4") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
