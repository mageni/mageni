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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818149");
  script_version("2021-06-15T03:25:17+0000");
  script_cve_id("CVE-2021-28554", "CVE-2021-28551", "CVE-2021-28552", "CVE-2021-28631",
                "CVE-2021-28632");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-15 10:41:11 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-10 11:53:47 +0530 (Thu, 10 Jun 2021)");
  script_name("Adobe Acrobat Classic 2020 Security Update (APSB21-37) - Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Acrobat
  Classic 2020 and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code on vulnerable system.");

  script_tag(name:"affected", value:"Adobe Acrobat Classic 2020 prior to version
  2020.004.30005 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Classic 2020 version
  2020.004.30005 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-37.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.001.30025"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.004.30005(2020.004.30005)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
