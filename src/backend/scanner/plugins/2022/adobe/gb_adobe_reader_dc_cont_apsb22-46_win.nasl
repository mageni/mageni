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

CPE = "cpe:/a:adobe:acrobat_reader_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826576");
  script_version("2022-10-14T06:52:58+0000");
  script_cve_id("CVE-2022-35691", "CVE-2022-38437", "CVE-2022-38450", "CVE-2022-42339",
                "CVE-2022-38449", "CVE-2022-42342");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-14 06:52:58 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-13 13:29:11 +0530 (Thu, 13 Oct 2022)");
  script_name("Adobe Reader DC Continuous Security Update (APSB22-46) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple stack-based buffer overflow errors.

  - Multiple out-of-bounds read errors.

  - A NULL Pointer dereference error.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and memory leak on an affected
  system.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  22.002.20212 and earlier on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader DC (Continuous)
  to version 22.003.20258 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-46.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Continuous/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"22.003.20258"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.003.20258", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
