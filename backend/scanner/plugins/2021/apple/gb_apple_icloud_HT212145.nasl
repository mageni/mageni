# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817899");
  script_version("2021-01-29T03:26:34+0000");
  script_cve_id("CVE-2020-29611", "CVE-2020-29618", "CVE-2020-29617", "CVE-2020-29619");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-01-29 11:05:10 +0000 (Fri, 29 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-28 12:48:59 +0530 (Thu, 28 Jan 2021)");
  script_name("Apple iCloud Security Updates (HT212145)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out-of-bounds write issue related to improper bounds checking.

  - Multiple out-of-bounds read errors related to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple iCloud versions before 12.0");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 12.0 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212145");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
icVer = infos['version'];
icPath = infos['location'];

if(version_is_less(version:icVer, test_version:"12.0"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"12.0", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
