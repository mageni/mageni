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
  script_oid("1.3.6.1.4.1.25623.1.0.826407");
  script_version("2022-08-17T07:23:27+0000");
  script_cve_id("CVE-2022-35665", "CVE-2022-35666", "CVE-2022-35667", "CVE-2022-35668",
                "CVE-2022-35670", "CVE-2022-35671", "CVE-2022-35678");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-17 07:23:27 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-11 10:47:36 +0530 (Thu, 11 Aug 2022)");
  script_name("Adobe Reader DC Continuous Security Update (APSB22-39) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple Improper Input Validation.

  - out-of-bounds read errors.

  - out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and leak memory on the target system.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  22.001.20169 and earlier on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader DC (Continuous)
  to version 22.002.20191 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-39.html");
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

if(version_is_less_equal(version:vers, test_version:"22.001.20169"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.002.20191 or later", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);