###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_HT208692_02.nasl 14292 2019-03-18 18:39:37Z cfischer $
#
# Apple MacOSX Security Updates(HT208692)-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.813113");
  script_version("$Revision: 14292 $");
  script_cve_id("CVE-2018-4104", "CVE-2018-4106", "CVE-2018-4144", "CVE-2018-4139",
                "CVE-2018-4136", "CVE-2018-4112", "CVE-2018-4175", "CVE-2018-4176",
                "CVE-2018-4156", "CVE-2018-4154", "CVE-2018-4151", "CVE-2018-4155",
                "CVE-2018-4158", "CVE-2018-4166");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 19:39:37 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-02 10:46:27 +0530 (Mon, 02 Apr 2018)");
  script_name("Apple MacOSX Security Updates(HT208692)-02");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An input validation issue.

  - A command injection issue in the handling of Bracketed Paste Mode.

  - A buffer overflow error.

  - Memory corruption due to a logic issue.

  - An out-of-bounds read error.

  - A validation issue in the handling of symlinks.

  - A logic issue.

  - A race condition.

  - A race condition was addressed with additional validation.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to read restricted memory, execute arbitrary code
  with system privileges, arbitrary command execution spoofing, gain access to user
  information, bypass code signing enforcement, launching arbitrary application
  and gain elevated privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.11.x through
  10.11.6, 10.12.x through 10.12.6, 10.13.x through 10.13.3");

  script_tag(name:"solution", value:"Apply the appropriate security patch from
  the reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208692");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[1-3]");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[1-3]" || "Mac OS X" >!< osName){
  exit(0);
}

if((osVer == "10.11.6") || (osVer == "10.12.6"))
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  ##https://en.wikipedia.org/wiki/OS_X_El_Capitan
  if(osVer == "10.11.6" && version_is_less(version:buildVer, test_version:"15G20015"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
  ##https://en.wikipedia.org/wiki/MacOS_Sierra
  else if(osVer == "10.12.6" && version_is_less(version:buildVer, test_version:"16G1314"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.11")
{
  if(version_is_less(version:osVer, test_version:"10.11.5")){
    fix = "Upgrade to latest OS release 10.11.6 and apply patch from vendor";
  }
}
else if(osVer =~ "^10\.12")
{
  if(version_is_less(version:osVer, test_version:"10.12.5")){
    fix = "Upgrade to latest OS release 10.12.6 and apply patch from vendor";
  }
}

else if(osVer =~ "^10\.13")
{
  if(version_is_less(version:osVer, test_version:"10.13.4")){
    fix = "10.13.4";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);