# Copyright (C) 2022 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826549");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2021-3156");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 23:16:40 +0530 (Thu, 22 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT212177)-02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to miltiple
  code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to vulnerable sudo version.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to elevate their privileges.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur 11.2, macOS Catalina 10.15.x
  prior to macOS Catalina 10.15.7 Supplemental Update, macOS Mojave 10.14.x
  prior to macOS Mojave 10.14.6 Security Update 2021-002.");

  script_tag(name:"solution", value:"Upgrade to version 11.2.1 or apply
  macOS Catalina 10.15.7 Supplemental Update for 10.15.x or apply Security Update 2021-002
  for macOS Mojave 10.14.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212177");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.15");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer == "11.2"){
  fix = "11.2.1";
}
else if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.6")){
  fix = "Upgrade to latest OS release and apply patch from vendor";
}

else if(osVer == "10.15.7")
{
  if(version_is_less(version:buildVer, test_version:"19H524"))
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
  if(version_is_less(version:buildVer, test_version:"18G8022"))
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

exit(99);
