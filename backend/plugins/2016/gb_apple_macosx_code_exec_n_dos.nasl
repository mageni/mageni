###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_code_exec_n_dos.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Code Execution And Denial of Service Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810210");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5096", "CVE-2013-7456",
                "CVE-2016-4637", "CVE-2016-4629", "CVE-2016-4630", "CVE-2016-1836",
                "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4483", "CVE-2016-4614",
                "CVE-2016-4615", "CVE-2016-4616", "CVE-2016-4619", "CVE-2016-4449",
                "CVE-2016-1684", "CVE-2016-4607", "CVE-2016-4608", "CVE-2016-4609",
                "CVE-2016-4610", "CVE-2016-4612", "CVE-2016-1798", "CVE-2015-8126");
  script_bugtraq_id(90696, 77568);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-22 11:05:47 +0530 (Tue, 22 Nov 2016)");
  script_name("Apple Mac OS X Code Execution And Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to code execution and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A null pointer dereference error.

  - An improper processing of .png file by libpng.

  - The multiple  memory corruption errors.

  - An access issue in the parsing of maliciously crafted XML files.

  - The multiple errors in php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service and to obtain sensitive
  information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.10.x through
  10.10.5 prior to build 14F1808");

  script_tag(name:"solution", value:"Apply the appropriate patch.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206567");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206903");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.10");
  script_xref(name:"URL", value:"https://www.apple.com");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName && osVer =~ "^10\.10")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(osVer == "10.10.5" && version_is_less(version:buildVer, test_version:"14F1808"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }

  else if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.4")){
    fix = "10.10.5 build 14F1808";
  }
}
if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);