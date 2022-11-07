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
  script_oid("1.3.6.1.4.1.25623.1.0.826606");
  script_version("2022-10-26T08:42:37+0000");
  script_cve_id("CVE-2022-42825", "CVE-2022-28739", "CVE-2022-32862");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-26 08:42:37 +0000 (Wed, 26 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-19 14:55:00 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2022-10-25 11:42:24 +0530 (Tue, 25 Oct 2022)");
  script_name("Apple MacOSX Security Update (HT213494)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A memory corruption issue.

  - An improper data protection.

  - Additional entitlements of the file system.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to access private information and conduct app termination or arbitrary code
  execution.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.6.1.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Monterey version
  12.6.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213494");
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

if(version_in_range(version:osVer, test_version:"12.0", test_version2:"12.6"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.6.1");
  security_message(data:report);
  exit(0);
}
exit(99);
