###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_dos_vuln_may09_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Adobe Reader/Acrobat Denial of Service Vulnerability (May09) (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800706");
  script_version("$Revision: 12629 $");
  script_cve_id("CVE-2009-1492");
  script_bugtraq_id(34736);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_name("Adobe Reader/Acrobat Denial of Service Vulnerability (May09)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to Denial of
  Service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw is due to memory corruption error in 'getAnnots' methods in the
  JavaScript API while processing malicious PDF files that calls this vulnerable
  method with crafted integer arguments.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause memory corruption or
  denial of service.");

  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.1 and prior on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.3.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34924");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50145");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2009/04/update_on_adobe_reader_issue.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";

if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_less_equal(version:readerVer, test_version:"9.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acroVer = get_app_version(cpe:CPE))
{
  if(version_is_less_equal(version:acroVer, test_version:"9.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
