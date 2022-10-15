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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826556");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2019-15126");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:15:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2022-09-26 14:32:57 +0530 (Mon, 26 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT210788) - 03");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a logic issue existed
  in the handling of state transitions.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  allow attackers in Wi-Fi range to view a small amount of network traffic.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.14.x prior to
  10.14.6 Security Update 2019-002 Mojave, 10.13.x prior to 10.13.6 Security Update
  2019-007 High Sierra.");

  script_tag(name:"solution", value:"Apply Security Update 2019-002 Mojave for 10.14.x
  and Security Update 2019-007 High Sierra for 10.13.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210788");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[45]" || "Mac OS X" >!< osName)
  exit(0);

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.13") {
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6") {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G10021")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.14") {
  if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.14.6") {
    if(osVer == "10.14.6" && version_is_less(version:buildVer, test_version:"18G2022")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
