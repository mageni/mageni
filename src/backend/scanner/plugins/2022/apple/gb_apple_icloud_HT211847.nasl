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

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826558");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2020-36521", "CVE-2020-9991", "CVE-2020-15358", "CVE-2020-9952");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 22:15:00 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"creation_date", value:"2022-09-28 09:52:31 +0530 (Wed, 28 Sep 2022)");
  script_name("Apple iCloud Security Update (HT211847)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors.

  - Improper checks.

  - Multiple issues in SQLite.");

  script_tag(name:"impact", value:"Successful exploitation allow remote attackers
  to cause denial of service and conduct cross site scripting attack.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.21");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud version 7.21 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211847");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"7.21"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.21", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
