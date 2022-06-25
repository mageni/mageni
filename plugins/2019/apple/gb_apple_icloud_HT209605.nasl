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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815005");
  script_version("2019-05-22T13:05:41+0000");
  script_cve_id("CVE-2019-8542", "CVE-2019-6232", "CVE-2019-8506", "CVE-2019-8535",
                "CVE-2019-6201", "CVE-2019-8518", "CVE-2019-8523", "CVE-2019-8524",
                "CVE-2019-8558", "CVE-2019-8559", "CVE-2019-8563", "CVE-2019-8515",
                "CVE-2019-8536", "CVE-2019-8544", "CVE-2019-7285", "CVE-2019-8556",
                "CVE-2019-8503", "CVE-2019-7292", "CVE-2019-8551", "CVE-2019-6236");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-22 13:05:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 14:42:55 +0530 (Tue, 26 Mar 2019)");
  script_name("Apple iCloud Security Updates( HT209605 )");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A buffer overflow error due to improper bounds checking.

  - A type confusion issue due to improper memory handling.

  - A memory corruption issue due to improper state management.

  - A cross-origin issue existed with the fetch API.

  - A memory corruption issue related to improper memory handling.

  - A use after free issue while processing maliciously crafted web content.

  - Logic and validation issues while processing maliciously crafted web content.

  - A race condition existed during the installation of iCloud.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to elevate privileges, conduct arbitrary code execution, cross site scripting
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.11");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.11 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209605");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

icVer = infos['version'];
icPath = infos['location'];

if(version_is_less(version:icVer, test_version:"7.11"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"7.11", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(0);
