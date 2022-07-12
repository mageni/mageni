###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_sandbox_bypass_vuln_aug14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Adobe Reader Sandbox Bypass Vulnerability - Aug14 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804813");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-0546");
  script_bugtraq_id(69193);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-19 12:05:17 +0530 (Tue, 19 Aug 2014)");
  script_name("Adobe Reader Sandbox Bypass Vulnerability - Aug14 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to sandbox bypass
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to some unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass sandbox restrictions
and execute native code in a privileged context.");
  script_tag(name:"affected", value:"Adobe Reader X version 10.x before 10.1.11 and XI version 11.x before 11.0.08
on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 10.1.11 or 11.0.08 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-19.html");
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

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^(10|11)")
{
  if((version_in_range(version:readerVer, test_version:"10.0", test_version2: "10.1.10"))||
     (version_in_range(version:readerVer, test_version:"11.0", test_version2: "11.0.07")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
