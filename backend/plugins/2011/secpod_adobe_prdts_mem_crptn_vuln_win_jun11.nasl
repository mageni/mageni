###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_mem_crptn_vuln_win_jun11.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Adobe Reader/Acrobat Memory Corruption Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902379");
  script_version("$Revision: 12018 $");
  script_cve_id("CVE-2011-2103");
  script_bugtraq_id(48247);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_name("Adobe Reader/Acrobat Memory Corruption Vulnerability (Windows)");


  script_tag(name:"summary", value:"This host has Adobe Reader/Acrobat installed, and is/are prone to memory
corruption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error, which leads to memory corruption.");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code in the context
of the user running the affected application.");
  script_tag(name:"affected", value:"Adobe Reader version 8.x through 8.2.6

Adobe Acrobat version 8.x through 8.2.6");
  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat and Reader version 8.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(readerVer =~ "^8")
  {
    if(version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2.6")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.2.6")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
exit(0);
