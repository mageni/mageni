###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_mem_crptn_vuln_macosx.nasl 11870 2018-10-12 11:12:45Z cfischer $
#
# Adobe Reader/Acrobat Multiple Memory Corruption Vulnerabilities - MAC OS X
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802559");
  script_version("$Revision: 11870 $");
  script_cve_id("CVE-2011-4370", "CVE-2011-4371", "CVE-2011-4372", "CVE-2011-4373");
  script_bugtraq_id(51348, 51351, 51349, 51350);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:12:45 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-16 11:41:01 +0530 (Mon, 16 Jan 2012)");
  script_name("Adobe Reader/Acrobat Multiple Memory Corruption Vulnerabilities - MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe products and are prone to multiple memory
corruption vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error can be exploited to corrupt memory.

  - A signedness error in rt3d.dll when parsing certain BMP image content can be
exploited to cause a heap-based buffer overflow via a specially crafted BMP
image embedded in a PDF document.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
context of the affected application or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader versions 9.x through 9.4.7 and 10.x through 10.1.1 on MAC OS X
Adobe Acrobat versions 9.x through 9.4.7 and 10.x through 10.1.1 on MAC OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5 or 10.1.2 or later.
Upgrade to Adobe Acrobat version 9.5 or 10.1.2 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45852/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026496");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

function version_check(ver)
{
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.4.7") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

CPE = "cpe:/a:adobe:acrobat_reader";

if(!readerVer = get_app_version(cpe:CPE))
{
  if(readerVer =~ "^(9|10)"){
    version_check(ver:readerVer);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");
if(acrobatVer){
  version_check(ver:acrobatVer);
}
