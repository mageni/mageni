###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_u3d_mem_crptn_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Adobe Reader/Acrobat 'U3D' Component Memory Corruption Vulnerability - Windows
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802542");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(50922, 51092);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:11:46 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Reader/Acrobat 'U3D' Component Memory Corruption Vulnerability - Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to memory
corruption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error while handling U3D data.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader versions 9.x through 9.4.6 and 10.x through 10.1.1 on Windows.

Adobe Acrobat versions 9.x through 9.4.6 and 10.x through 10.1.1 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader or Acrobat version 9.4.7 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47133/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-30.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

function version_check(ver)
{
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.4.6") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(readerVer =~ "^(9|10)"){
    version_check(ver:readerVer);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  version_check(ver:acrobatVer);
}
exit(0);
