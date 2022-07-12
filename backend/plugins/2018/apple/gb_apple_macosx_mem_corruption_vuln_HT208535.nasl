###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mem_corruption_vuln_HT208535.nasl 14292 2019-03-18 18:39:37Z cfischer $
#
# Apple MacOSX Memory Corruption Vulnerability (HT208535)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812939");
  script_version("$Revision: 14292 $");
  script_cve_id("CVE-2018-4124");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 19:39:37 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-21 18:05:29 +0530 (Wed, 21 Feb 2018)");
  script_name("Apple MacOSX Memory Corruption Vulnerability (HT208535)");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a memory corruption
  issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct denial-of-service or execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.13.x prior to
  10.13.3 build 17D102 or build 17D2102");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.13.3 build 17D102 or build 17D2102 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208535");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  script_xref(name:"URL", value:"https://www.apple.com");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13"){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.2")){
  fix = "10.13.3 build 17D102 or build 17D2102";
}

else if(osVer == "10.13.3")
{
  buildVer = get_kb_item("ssh/login/osx_build");

  ##https://en.wikipedia.org/wiki/MacOS_High_Sierra
  if(buildVer && ((buildVer  != "17D102") && (buildVer != "17D2102")))
  {
    fix = "10.13.3 build 17D102 or build 17D2102";
    osVer = osVer + " Build " + buildVer ;
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);