###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_july15_win.nasl  2015-07-21 11:27:48 July$
#
# Adobe Acrobat Multiple Vulnerabilities - 01 July15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805682");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5115", "CVE-2015-5114", "CVE-2015-5113", "CVE-2015-5111",
                "CVE-2015-5110", "CVE-2015-5109", "CVE-2015-5108", "CVE-2015-5107",
                "CVE-2015-5106", "CVE-2015-5105", "CVE-2015-5104", "CVE-2015-5103",
                "CVE-2015-5102", "CVE-2015-5101", "CVE-2015-5100", "CVE-2015-5099",
                "CVE-2015-5098", "CVE-2015-5097", "CVE-2015-5096", "CVE-2015-5095",
                "CVE-2015-5094", "CVE-2015-5093", "CVE-2015-5092", "CVE-2015-5091",
                "CVE-2015-5090", "CVE-2015-5089", "CVE-2015-5088", "CVE-2015-5087",
                "CVE-2015-5086", "CVE-2015-5085", "CVE-2015-4452", "CVE-2015-4451",
                "CVE-2015-4450", "CVE-2015-4449", "CVE-2015-4448", "CVE-2015-4447",
                "CVE-2015-4446", "CVE-2015-4445", "CVE-2015-4444", "CVE-2015-4443",
                "CVE-2015-4441", "CVE-2015-4438", "CVE-2015-4435", "CVE-2015-3095",
                "CVE-2014-8450", "CVE-2014-0566");
  script_bugtraq_id(75740, 75739, 75746, 75741, 75749, 75747, 69825, 75748, 75742,
                    75738, 75743, 75737, 75735, 75402);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-21 11:27:48 +0530 (Tue, 21 Jul 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Acrobat Multiple Vulnerabilities - 01 July15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple memory corruption vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - Multiple integer over flow vulnerabilities.

  - Multiple buffer over flow vulnerabilities.

  - Some unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service, bypass certain security restrictions,
  to obtain sensitive information, execute arbitrary code and compromise a
  user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat 10.x before 10.1.15
  and 11.x before 11.0.12 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 10.1.15 or
  11.0.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75402");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.1.14"))
{
  fix = "10.1.15";
  VULN = TRUE ;
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.11"))
{
  fix = "11.0.12";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + readerVer + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report);
  exit(0);
}




