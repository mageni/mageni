# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.816718");
  script_version("2020-03-29T02:34:12+0000");
  script_cve_id("CVE-2020-3910", "CVE-2020-3909", "CVE-2020-3911", "CVE-2020-3901",
                "CVE-2020-3887", "CVE-2020-3895", "CVE-2020-3900", "CVE-2020-3894",
                "CVE-2020-3897", "CVE-2020-9783", "CVE-2020-3899", "CVE-2020-3902",
                "CVE-2020-3885");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-30 09:58:56 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 16:15:07 +0530 (Thu, 26 Mar 2020)");
  script_name("Apple iCloud Security Updates (HT211106)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple buffer overflow issues due to improper size validation and bounds checking.

  - A type confusion issue due to improper memory handling.

  - A logic issue improper restrictions.

  - A memory corruption issue due to improper memory handling.

  - A race condition issue due to insufficient validation.

  - A use after free issue due to improper memory management.

  - A memory consumption issue due to improper memory handling.

  - An input validation issue due to improper validation.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, read restricted memory, and launch cross site scripting
  attacks.");

  script_tag(name:"affected", value:"Apple iCloud versions before 10.9.3");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 10.9.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211106");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(icVer =~ "^10\." && version_is_less(version:icVer, test_version:"10.9.3"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"10.9.3", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
