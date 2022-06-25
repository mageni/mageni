###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_uri_remote_code_exec_vuln_oct07_win.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Adobe Reader URI Handler Remote Code Execution Vulnerabilities Oct07 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804376");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2007-5020", "CVE-2007-3896");
  script_bugtraq_id(25748, 25945);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-10 10:20:46 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader URI Handler Remote Code Execution Vulnerabilities Oct07 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to remote code execution
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws are due to an input validation error when handling specially crafted
URIs with registered URI handlers.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
compromise a user's system.");
  script_tag(name:"affected", value:"Adobe Reader version 8.1 and prior on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 8.1.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/26201");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1018723");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1018822");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/36722");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb07-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  script_xref(name:"URL", value:"http://get.adobe.com/reader");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3)<= 0)
{
  exit(0);
}

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer)
{
  if(version_is_less_equal(version:readerVer, test_version:"8.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
