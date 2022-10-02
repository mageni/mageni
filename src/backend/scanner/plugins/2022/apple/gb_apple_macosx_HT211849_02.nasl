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
  script_oid("1.3.6.1.4.1.25623.1.0.826551");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2020-9986", "CVE-2020-9954");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-09 20:28:00 +0000 (Wed, 09 Dec 2020)");
  script_tag(name:"creation_date", value:"2022-09-21 23:08:28 +0530 (Wed, 21 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT211849) - 02");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities
  according to Apple security advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A file access issue existed with certain home folder files. This was addressed with improved access restrictions.

  - A buffer overflow issue was addressed with improved memory handling.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to execute arbitrary code, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions,
  10.15.x prior to 10.15.7.");

  script_tag(name:"solution", value:"Upgrade Apple Mac OS X Catalina to 10.15.7 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211849");
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
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15" || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"10.15.7"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.15.7");
  security_message(data:report);
  exit(0);
}
exit(0);
