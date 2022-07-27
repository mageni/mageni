# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814888");
  script_version("2019-05-22T13:43:48+0000");
  script_cve_id("CVE-2019-8603", "CVE-2019-8605", "CVE-2019-8604", "CVE-2019-8574",
                "CVE-2019-8591", "CVE-2019-8590");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 13:43:48 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-14 10:43:13 +0530 (Tue, 14 May 2019)");
  script_name("Apple MacOSX Security Updates (HT210119) - 02");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A validation issue with improper input sanitization.

  - A use after free issue with improper memory management.

  - A memory corruption issue with improper memory handling.

  - A type confusion issue with improper memory handling.

  - A logic issue with improper restrictions.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to read restricted memory, execute arbitrary code with
  system privileges, cause system termination or write to the kernel memory.");

  script_tag(name:"affected", value:"Apple Mac OS X versions,
  10.12.x through 10.12.6, 10.13.x through 10.13.6, 10.14.x through 10.14.4.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.12.6
  build 16G2016, or 10.13.6 build 17G7024 or 10.14.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210119");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[2-4]\.");

  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit(0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer|| osVer !~ "^10\.1[2-4]\."|| "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.12.6")
  {
    if(osVer == "10.12.6" && version_is_less(version:buildVer, test_version:"16G2016"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.13")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G7024"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer == "10.14.4"){
  fix = "10.14.5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
exit(99);
