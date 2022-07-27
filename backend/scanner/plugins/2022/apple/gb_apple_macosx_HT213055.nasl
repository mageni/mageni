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
  script_oid("1.3.6.1.4.1.25623.1.0.819976");
  script_version("2022-02-01T06:17:45+0000");
  script_cve_id("CVE-2021-30960", "CVE-2022-22585", "CVE-2022-22587", "CVE-2022-22593",
                "CVE-2022-22579", "CVE-2022-22583", "CVE-2021-30972");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-01-31 08:48:29 +0530 (Mon, 31 Jan 2022)");
  script_name("Apple MacOSX Security Update (HT213055)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple buffer overflow issues due to improper memory handling.

  - An issue existed within the path validation logic for symlinks.

  - A memory corruption issue due to improper input validation.

  - Multiple state management errors.

  - An inherited permissions issue.

  - An improper check leading to bypass of certain Privacy preferences.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, privilege escalation, restricted file
  access and information disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.3.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213055");
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
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.2"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.3");
  security_message(data:report);
  exit(0);
}
exit(99);
