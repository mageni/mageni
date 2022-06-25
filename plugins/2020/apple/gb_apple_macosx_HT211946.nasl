# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817840");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2020-27950", "CVE-2020-27932", "CVE-2020-27930");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-19 11:32:07 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-17 13:09:38 +0530 (Tue, 17 Nov 2020)");
  script_name("Apple MacOSX Security Updates(HT211946)");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A memory initialization issue.

  - A type confusion issue related to improper state handling.

  - A memory corruption issue related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  execute arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions High Sierra 10.13.6
  before Security Update 2020-006 High Sierra, Mojave 10.14.6 before
  Security Update 2020-006 Mojave");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.6 build
  17G14042 or 10.14.6 build 18G6042 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211946");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  script_xref(name:"URL", value:"https://www.apple.com.");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[34]" || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.13.6")
{
  if(version_is_less(version:buildVer, test_version:"17G14042"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

else if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.14.6")
{
  if(version_is_less(version:buildVer, test_version:"18G6042"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(0);
