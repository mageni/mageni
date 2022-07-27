# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817872");
  script_version("2020-12-16T06:26:32+0000");
  script_cve_id("CVE-2020-10002", "CVE-2020-13434", "CVE-2020-13435", "CVE-2020-13630",
                "CVE-2020-13631", "CVE-2020-27911", "CVE-2020-27912", "CVE-2020-27917",
                "CVE-2020-27918", "CVE-2020-9849", "CVE-2020-9876", "CVE-2020-9947",
                "CVE-2020-9951", "CVE-2020-9961", "CVE-2020-9981", "CVE-2020-9983");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-16 11:44:11 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-08 14:23:33 +0530 (Tue, 08 Dec 2020)");
  script_name("Apple iCloud Security Updates (HT211935)");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple use after free issues due to improper memory management.

  - Multiple out-of-bounds write errors due to improper input validation and
    bounds checking.

  - An integer overflow error due to improper validation.

  - An information disclosure issue due to improper state management.

  - Memory corruption and logic issues due to improper state management.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, read arbitrary files, and launch denial of service
  attacks.");

  script_tag(name:"affected", value:"Apple iCloud versions before 11.5");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 11.5 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211935");
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

if(version_is_less(version:icVer, test_version:"11.5"))
{
  report = report_fixed_ver(installed_version:icVer, fixed_version:"11.5", install_path:icPath);
  security_message(data:report);
  exit(0);
}
exit(99);
