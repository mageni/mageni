###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Mac OS X Code Execution Vulnerability May-2018
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
  script_oid("1.3.6.1.4.1.25623.1.0.813366");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-7596");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-14 15:20:12 +0530 (Mon, 14 May 2018)");
  script_name("Apple Mac OS X Code Execution Vulnerability May-2018");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code with kernel privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.1, 10.11.x through
  10.11.6 and 10.10.x through 10.10.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.2 or later or apply appropriate security update for 10.11.x and 10.10.x versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207423");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[0-2]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[0-2]" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.11.6") || (osVer == "10.10.5"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  ##https://en.wikipedia.org/wiki/OS_X_El_Capitan
  if(osVer == "10.11.6" && version_is_less_equal(version:buildVer, test_version:"15G1108"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
  ##https://en.wikipedia.org/wiki/OS_X_Yosemite
  else if(osVer == "10.10.5" && version_is_less_equal(version:buildVer, test_version:"14F2009"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.6")){
    fix = "Upgrade to latest OS release 10.11.6 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.10")
{
  if(version_is_less(version:osVer, test_version:"10.10.5")){
    fix = "Upgrade to latest OS release 10.10.5 and apply patch from vendor";
  }
}

else if(osVer == "10.12.1"){
  fix = "10.12.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);