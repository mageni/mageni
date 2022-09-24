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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:framemaker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826468");
  script_version("2022-09-19T10:11:35+0000");
  script_cve_id("CVE-2021-39835", "CVE-2021-40697", "CVE-2021-39833", "CVE-2021-39834",
                "CVE-2021-39832", "CVE-2021-39830", "CVE-2021-39829", "CVE-2021-39831",
                "CVE-2021-39862", "CVE-2021-39865");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-08 14:29:00 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2022-09-15 11:33:35 +0530 (Thu, 15 Sep 2022)");
  script_name("Adobe Framemaker Security Updates (apsb21-74) - Windows");

  script_tag(name:"summary", value:"Adobe Framemaker is prone to multiple
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Use After Free error.

  - Multiple out-of-bounds read errors.

  - Access of Memory Location After End of Buffer

  - An Out-of-bounds Write Error.

  - Heap-based Buffer Overflow.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and escalate privilege on the system.");

  script_tag(name:"affected", value:"Adobe Framemaker 2019 Update 8 and earlier,
  2020 Release Update 2 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Framemaker 2020 Release
  Update 3 or later or Apply the 2019 Release Update 8 (hotfix). Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"30");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-74.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_framemaker_detect_win.nasl");
  script_mandatory_keys("AdobeFrameMaker/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"2020.0", test_version2:"2020.0.2"))
{
  fix = "2020.0.3 or later.";
}
else if(version_is_less_equal(version:vers, test_version:"2019.0.8"))
{
  fix = "Apply the 2019 Release Update 8 (hotfix).";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
