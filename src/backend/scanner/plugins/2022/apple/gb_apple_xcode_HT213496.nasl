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

CPE = "cpe:/a:apple:xcode";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822747");
  script_version("2022-11-08T10:12:11+0000");
  script_cve_id("CVE-2022-29187", "CVE-2022-39253", "CVE-2022-39260", "CVE-2022-42797");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 09:05:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-11-03 17:48:36 +0530 (Thu, 03 Nov 2022)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Xcode Security Update (HT213496)");

  script_tag(name:"summary", value:"Apple Xcode is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An input validation error in IDE Xcode Server.

  - Improper checks.

  - Multiple issues in git.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, disclose sensitive information, execute arbitrary code
  and cause denial of service condition on an affected system.");

  script_tag(name:"affected", value:"Apple Xcode prior to version 14.1 on
  macOS Monterey 12 and later.");

  script_tag(name:"solution", value:"Upgrade to Apple Xcode 14.1 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213496");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl", "gb_xcode_detect_macosx.nasl");
  script_mandatory_keys("ssh/login/osx_version", "Xcode/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\."){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

xcVer = infos['version'];
xcpath = infos['location'];

if(version_is_less(version:xcVer, test_version:"14.1"))
{
  report = report_fixed_ver(installed_version:xcVer, fixed_version:"14.1", install_path:xcpath);
  security_message(data:report);
  exit(0);
}
exit(0);
