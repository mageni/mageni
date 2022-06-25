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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818886");
  script_version("2022-03-31T07:10:52+0000");
  script_cve_id("CVE-2021-28561", "CVE-2021-28560", "CVE-2021-28558", "CVE-2021-28557",
                "CVE-2021-28555", "CVE-2021-28565", "CVE-2021-28564", "CVE-2021-21044",
                "CVE-2021-21038", "CVE-2021-28559", "CVE-2021-28562", "CVE-2021-28550",
                "CVE-2021-28553");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-29 17:17:58 +0530 (Tue, 29 Mar 2022)");
  script_name("Adobe Reader 2017 Security Update (APSB21-29) - Windows");

  script_tag(name:"summary", value:"Adobe Reader 2017 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple buffer overflow errors.

  - An use-after-free error.

  - Multiple out-of-bounds read/write errors.

  - Privilege escalation error");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, diclose sensitive information and escalate privileges.");

  script_tag(name:"affected", value:"Adobe Reader 2017 version prior to
  2017.011.30196 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader 2017 version
  2017.011.30196 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-29.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30194"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30196(2017.011.30196)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
