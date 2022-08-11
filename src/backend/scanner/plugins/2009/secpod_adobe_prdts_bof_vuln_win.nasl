###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_bof_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Buffer Overflow Vulnerability in Adobe Acrobat and Reader (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900320");
  script_version("$Revision: 12629 $");
  script_cve_id("CVE-2009-0658", "CVE-2009-0927", "CVE-2009-0193", "CVE-2009-0928",
                "CVE-2009-1061", "CVE-2009-1062");
  script_bugtraq_id(33751, 34169, 34229);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_name("Buffer Overflow Vulnerability in Adobe Acrobat and Reader (Windows)");

  script_tag(name:"summary", value:"This host has Adobe Acrobat or Adobe Reader installed, and is prone to buffer
overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This issue is due to error in array indexing while processing JBIG2 streams
and unspecified vulnerability related to a JavaScript method.");
  script_tag(name:"impact", value:"This can be exploited to corrupt arbitrary memory via a specially crafted PDF
file, related to a non-JavaScript function call and to execute arbitrary code
in context of the affected application.");
  script_tag(name:"affected", value:"Adobe Reader/Acrobat version 9.x < 9.1, 8.x < 8.1.4, 7.x < 7.1.1 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Reader/Acrobat version 9.1 or 7.1.1 or 8.1.4 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33901");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-03.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-04.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa09-01.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33751-PoC.pl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
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
  if(readerVer =~ "^(7|8|9)")
  {
    if(version_in_range(version:readerVer, test_version:"7.0", test_version2:"7.1.0")||
       version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.3")||
       readerVer =~ "9.0"){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acrobatVer = get_app_version(cpe:CPE))
{
  if(version_in_range(version:acrobatVer, test_version:"7.0", test_version2:"7.1.0")||
     version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.1.3")||
     acrobatVer =~ "9.0")
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
