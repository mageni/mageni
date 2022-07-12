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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818190");
  script_version("2021-08-17T06:00:15+0000");
  script_cve_id("CVE-2021-28591", "CVE-2021-28592", "CVE-2021-28593", "CVE-2021-36008",
                "CVE-2021-36009", "CVE-2021-36010", "CVE-2021-36011");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-17 13:02:36 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-12 13:09:23 +0530 (Thu, 12 Aug 2021)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB21-42) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe August update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple out-of-bounds write errors.

  - An use after free error.

  - Multiple out-of-bounds read error.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and read arbitrary files on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator 2021 25.2.3 and earlier
  versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator 2021 version
  25.3 or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb21-42.html");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_win.nasl");
  script_mandatory_keys("Adobe/Illustrator/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"25.0", test_version2:"25.2.3"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:'25.3', install_path:path);
  security_message(data: report);
  exit(0);
}
exit(99);
