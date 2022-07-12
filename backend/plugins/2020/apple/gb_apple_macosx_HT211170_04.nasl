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
  script_oid("1.3.6.1.4.1.25623.1.0.817133");
  script_version("2020-05-29T08:53:11+0000");
  script_cve_id("CVE-2020-9817", "CVE-2020-9816", "CVE-2020-9830", "CVE-2020-9833",
                "CVE-2020-9832", "CVE-2020-9834", "CVE-2020-9811", "CVE-2020-9812",
                "CVE-2020-9841", "CVE-2020-9789", "CVE-2020-9790", "CVE-2019-20044",
                "CVE-2020-9808", "CVE-2020-9809", "CVE-2020-9847", "CVE-2020-9822",
                "CVE-2020-9821", "CVE-2020-9826", "CVE-2020-9797", "CVE-2020-9839",
                "CVE-2019-14868", "CVE-2020-9813", "CVE-2020-9814", "CVE-2020-9795");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 12:17:06 +0530 (Wed, 27 May 2020)");
  script_name("Apple MacOSX Security Updates(HT211170)-04");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in permissions issued.

  - An out-of-bounds write error.

  - A memory initialization error.

  - Multiple out-of-bounds read errors.

  - Multiple memory corruption issues.

  - An error in state management.

  - An integer overflow.

  - An authorization issue.

  - An error in input validation.

  - Presence of vulnerable code.

  - A race condition.

  - An error in the handling of environment variables.

  - A logic error resulting in memory corruption.

  - A use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers gain root privileges, conduct a denial-of-service, execute arbitrary
  code, read kernel memory, elevate privileges, escape sandbox and gain access to
  sensitive information.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.13.x through
  10.13.6, 10.14.x through 10.14.6 and 10.15.x through 10.15.4");

  script_tag(name:"solution", value:"Apply security update 2020-003 for Apple
  Mac OS X version 10.13.x and 10.14.x, or upgrade to version 10.15.5 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211170");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = "";
osVer = "";
buildVer = "";


osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[345]" || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^(10\.13)")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G13033"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer =~ "^(10\.14)")
{
  if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.14.6")
  {
    if(osVer == "10.14.6" && version_is_less(version:buildVer, test_version:"18G5033"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.4")) {
  fix = "10.15.5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
