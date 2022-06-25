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
  script_oid("1.3.6.1.4.1.25623.1.0.815218");
  script_version("2019-06-17T04:49:23+0000");
  script_cve_id("CVE-2019-8577", "CVE-2019-8600", "CVE-2019-8598", "CVE-2019-8602",
                "CVE-2019-8607", "CVE-2019-6237", "CVE-2019-8571", "CVE-2019-8583",
                "CVE-2019-8584", "CVE-2019-8586", "CVE-2019-8587", "CVE-2019-8594",
                "CVE-2019-8595", "CVE-2019-8596", "CVE-2019-8597", "CVE-2019-8601",
                "CVE-2019-8608", "CVE-2019-8609", "CVE-2019-8610", "CVE-2019-8611",
                "CVE-2019-8615", "CVE-2019-8619", "CVE-2019-8622", "CVE-2019-8623",
                "CVE-2019-8628");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-17 04:49:23 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-14 10:13:10 +0530 (Fri, 14 Jun 2019)");
  script_name("Apple iCloud Security Updates (HT210212)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An input validation issue due to improper memory handling.

  - Multiple memory corruption issues due to improper input validation
    and memory handling.

  - An out-of-bounds read issue due to improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation allows remote
  attackers to gain elevated privileges, execute arbitrary code and read
  restricted memory.");

  script_tag(name:"affected", value:"Apple iCloud versions before 10.4");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 10.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-bn/HT210212");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
icVer = infos['version'];
icPath = infos['location'];

if(version_is_less(version:icVer, test_version:"10.4"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"10.4", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(0);
