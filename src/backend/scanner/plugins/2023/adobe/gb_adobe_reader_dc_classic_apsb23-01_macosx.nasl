# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826775");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2023-21579", "CVE-2023-21581", "CVE-2023-21585", "CVE-2023-21586",
                "CVE-2023-21604", "CVE-2023-21605", "CVE-2023-21606", "CVE-2023-21607",
                "CVE-2023-21608", "CVE-2023-21609", "CVE-2023-21610", "CVE-2023-21611",
                "CVE-2023-21612", "CVE-2023-21613", "CVE-2023-21614", "CVE-2023-22240",
                "CVE-2023-22241", "CVE-2023-22242");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 15:28:39 +0530 (Wed, 11 Jan 2023)");
  script_name("Adobe Reader Classic 2020 Security Update (APSB23-01) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple stack-based buffer overflow errors.

  - Violation of Secure Design Principles.

  - An integer overflow or wraparound error.

  - Multiple out-of-bounds read or write errors.

  - A NULL Pointer dereference error.

  - An use after free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges, execute arbitrary code, cause denial of service and
  memory leak on an affected system.");

  script_tag(name:"affected", value:"Adobe Reader Classic 2020 version
  20.005.30418 and earlier on Mac OS X.");

  script_tag(name:"solution", value:"Update Adobe Reader Classic 2020 to
  version 20.005.30436 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb23-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.005.30418"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.005.30436(2020.005.30436)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
