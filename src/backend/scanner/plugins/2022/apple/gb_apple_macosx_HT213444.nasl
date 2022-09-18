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
  script_oid("1.3.6.1.4.1.25623.1.0.826507");
  script_version("2022-09-14T10:57:19+0000");
  script_cve_id("CVE-2022-32902", "CVE-2022-32896", "CVE-2022-32911", "CVE-2022-32864",
                "CVE-2022-32917", "CVE-2022-32883", "CVE-2022-32908", "CVE-2022-32900");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-14 10:57:19 +0000 (Wed, 14 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 15:37:10 +0530 (Tue, 13 Sep 2022)");
  script_name("Apple MacOSX Security Update (HT213444)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper state management.

  - An improper input validation.

  - An improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  gain elevated privileges, execute arbitrary code with kernel privileges,
  disclose sensitive information and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.6.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Monterey version
  12.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213444");
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
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"12.6"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.6");
  security_message(data:report);
  exit(0);
}
exit(99);
