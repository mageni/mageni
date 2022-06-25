###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_xss_n_dos_vuln_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Reader Cross-Site Scripting & Denial of Service Vulnerabilities (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804396");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2007-0045", "CVE-2007-0048");
  script_bugtraq_id(21858);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-15 11:40:57 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader Cross-Site Scripting & Denial of Service Vulnerabilities (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to cross site scripting
and denial of service vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to,

  - the browser plug-in does not validate user supplied input to the hosted PDF
file before returning the input to the user.

  - some unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause memory corruption,
conduct denial of service attack and the execution of arbitrary script code in
a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Adobe Reader version 9.x before 9.2, 8.x before 8.1.7, 7.x before 7.1.4, 7.0.8
and earlier on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.2 or 8.1.7 or 7.1.4 or 7.0.9 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36983");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1017469");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  script_xref(name:"URL", value:"http://get.adobe.com/reader");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer)
{
  if(version_is_less_equal(version:readerVer, test_version:"7.0.8")||
    version_in_range(version:readerVer, test_version:"7.1.0", test_version2:"7.1.3")||
    version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.1.6")||
    version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
