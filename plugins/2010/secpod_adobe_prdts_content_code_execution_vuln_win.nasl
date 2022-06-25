###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_content_code_execution_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Products Content Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902303");
  script_version("$Revision: 12653 $");
  script_bugtraq_id(43205);
  script_cve_id("CVE-2010-2884");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_name("Adobe Products Content Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host has Adobe Acrobat or Adobe Reader or Adobe flash Player installed,
and is prone to code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is caused by an unspecified error when processing malformed 'Flash'
or '3D' and 'Multimedia' content within a PDF document, which could be
exploited by attackers to execute arbitrary code by convincing a user to open
a specially crafted PDF file.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to corrupt memory and execute
arbitrary code on the system with elevated privileges.");
  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.3.4 and prior on Windows.

Adobe Flash Player version 10.1.82.76 and prior on Windows");
  script_tag(name:"solution", value:"Upgrade to adobe flash version 10.1.85.3 or later and Adobe Reader/Acrobat
version 9.4 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61771");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2349");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2348");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa10-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less_equal(version:readerVer, test_version:"9.3.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less_equal(version:acrobatVer, test_version:"9.3.4")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:flash_player";
if(flashVer = get_app_version(cpe:CPE))
{
  if(version_is_less_equal(version:flashVer, test_version:"10.1.82.76")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
