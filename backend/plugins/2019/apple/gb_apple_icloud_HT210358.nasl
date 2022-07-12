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
  script_oid("1.3.6.1.4.1.25623.1.0.815262");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2019-13118", "CVE-2019-8658", "CVE-2019-8690", "CVE-2019-8644",
                "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672",
                "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678",
                "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683",
                "CVE-2019-8684", "CVE-2019-8685", "CVE-2019-8686", "CVE-2019-8687",
                "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8649");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-24 16:08:55 +0530 (Wed, 24 Jul 2019)");
  script_name("Apple iCloud Security Updates(HT210358)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A stack overflow issue.

  - Multiple logic issues in the handling of document loads and synchronous page loads.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to view sensitive information, conduct cross site scripting attacks and execute
  arbitrary code by processing maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iCloud version 10.x before 10.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 10.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-in/HT210358");
  script_xref(name:"URL", value:"https://support.apple.com/en-in/HT204283");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

if(icVer =~ "^10\." && version_is_less(version:icVer, test_version:"10.6"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"10.6", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
