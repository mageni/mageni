###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_oct15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Adobe Acrobat Multiple Vulnerabilities - 01 October15 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806506");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5583", "CVE-2015-5586", "CVE-2015-6683", "CVE-2015-6684",
                "CVE-2015-6685", "CVE-2015-6686", "CVE-2015-6687", "CVE-2015-6688",
                "CVE-2015-6689", "CVE-2015-6690", "CVE-2015-6691", "CVE-2015-6692",
                "CVE-2015-6693", "CVE-2015-6694", "CVE-2015-6695", "CVE-2015-6696",
                "CVE-2015-6697", "CVE-2015-6698", "CVE-2015-6699", "CVE-2015-6700",
                "CVE-2015-6701", "CVE-2015-6702", "CVE-2015-6703", "CVE-2015-6704",
                "CVE-2015-6705", "CVE-2015-6706", "CVE-2015-6707", "CVE-2015-6708",
                "CVE-2015-6709", "CVE-2015-6710", "CVE-2015-6711", "CVE-2015-6712",
                "CVE-2015-6713", "CVE-2015-6714", "CVE-2015-6715", "CVE-2015-6716",
                "CVE-2015-6717", "CVE-2015-6718", "CVE-2015-6719", "CVE-2015-6720",
                "CVE-2015-6721", "CVE-2015-6722", "CVE-2015-6723", "CVE-2015-6724",
                "CVE-2015-6725", "CVE-2015-7614", "CVE-2015-7615", "CVE-2015-7616",
                "CVE-2015-7617", "CVE-2015-7618", "CVE-2015-7619", "CVE-2015-7620",
                "CVE-2015-7621", "CVE-2015-7622", "CVE-2015-7623", "CVE-2015-7624",
                "CVE-2015-7829", "CVE-2015-7650", "CVE-2015-8458");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-20 11:06:46 +0530 (Tue, 20 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Acrobat Multiple Vulnerabilities - 01 October15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper EScript exception handling.

  - Some use-after-free vulnerabilities.

  - Some buffer overflow vulnerabilities.

  - Some memory leak vulnerabilities.

  - Some security bypass vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - Some Javascript API execution restriction bypass vulnerabilities.

  - Mishandling of junctions in the Synchronizer directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial of service, unauthorized disclosure of information,
  unauthorized modification, disruption of service, bypass certain access restrictions
  and execution restrictions, to delete arbitrary files, to obtain sensitive
  information, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat 10.1.x before 10.1.16
  and 11.x before 11.0.13 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 10.1.16 or
  11.0.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"10.1", test_version2:"10.1.15"))
{
  fix = "10.1.16";
  VULN = TRUE ;
}

else if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.12"))
{
  fix = "11.0.13";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + readerVer + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report);
  exit(0);
}
