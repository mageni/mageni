###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_HT208742.nasl 14292 2019-03-18 18:39:37Z cfischer $
#
# Apple MacOSX Security Updates(HT208742)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813318");
  script_version("$Revision: 14292 $");
  script_cve_id("CVE-2018-4206", "CVE-2018-4187");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 19:39:37 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-25 11:47:33 +0530 (Wed, 25 Apr 2018)");
  script_name("Apple MacOSX Security Updates(HT208742)");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A memory corruption issue related to improper error handling.

  - A spoofing issue existed in the handling of URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges and conduct UI spoofing.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.13.x through
  10.13.4");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.4 and
  apply the appropriate security update. For updates refer the reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208742");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName){
  exit(0);
}

##https://en.wikipedia.org/wiki/MacOS_High_Sierra
if(osVer == "10.13.4")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(version_is_less(version:buildVer, test_version:"17E202"))
  {
    fix = "Apply security update from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}
else if(version_is_less(version:osVer, test_version:"10.13.4")){
  fix = "Upgrade to latest OS release 10.13.4 and apply security update from vendor";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);