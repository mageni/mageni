###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_jan10_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Reader/Acrobat Multiple Vulnerabilities -jan10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800427");
  script_version("$Revision: 12653 $");
  script_cve_id("CVE-2009-3953", "CVE-2009-3954", "CVE-2009-3955", "CVE-2009-3956",
                "CVE-2009-3957", "CVE-2009-3958", "CVE-2009-3959", "CVE-2009-4324",
                "CVE-2010-1278");
  script_bugtraq_id(37758, 37761, 37757, 37763, 37760, 37759, 37756, 39615);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities - Jan10 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"For more information refer the references section.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause memory corruption or
  denial of service.");

  script_tag(name:"affected", value:"Adobe Reader and Acrobat 9.x before 9.3, 8.x before 8.2 on Windows.");

  script_tag(name:"solution", value:"Update to Adobe Reader and Acrobat 8.2, 9.3 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:adobe:acrobat_reader";
if(readerVer = get_app_version(cpe:CPE, nofork:TRUE))
{
  if(readerVer =~ "^[89]\.")
  {
    if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.2") ||
       version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

CPE = "cpe:/a:adobe:acrobat";
if(acroVer = get_app_version(cpe:CPE))
{
  if(version_in_range(version:acroVer, test_version:"9.0", test_version2:"9.2") ||
     version_in_range(version:acroVer, test_version:"8.0", test_version2:"8.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
