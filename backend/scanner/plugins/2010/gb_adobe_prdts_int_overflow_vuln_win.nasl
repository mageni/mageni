###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_int_overflow_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801419");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2862");
  script_name("Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40766");
  script_xref(name:"URL", value:"http://www.zdnet.co.uk/news/security-threats/2010/08/04/adobe-confirms-pdf-security-hole-in-reader-40089737/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation results in memory corruption via a PDF
file containing a specially crafted TrueType font.");
  script_tag(name:"affected", value:"Adobe Reader version 8.2.3 and 9.3.3

Adobe Acrobat version 9.3.3 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'CoolType.dll'
when parsing the 'maxCompositePoints' field value in the 'maxp' (Maximum Profile)
table of a TrueType font.");
  script_tag(name:"solution", value:"Upgrade to version 8.2.4 or 9.3.4 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe products and are prone to font
parsing integer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(version_is_equal(version:readerVer, test_version:"8.2.3") ||
     version_is_equal(version:readerVer, test_version:"9.3.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_is_equal(version:acrobatVer, test_version:"9.3.3")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
