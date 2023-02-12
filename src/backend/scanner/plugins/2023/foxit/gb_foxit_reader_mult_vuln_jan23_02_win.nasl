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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826901");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-32774", "CVE-2022-37332", "CVE-2022-38097", "CVE-2022-40129",
                "CVE-2022-43637", "CVE-2022-43638", "CVE-2022-43639", "CVE-2022-43640",
                "CVE-2022-43641");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-30 17:08:32 +0530 (Mon, 30 Jan 2023)");
  script_name("Foxit Reader Multiple Vulnerabilities January-02 2023");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple use-after-free vulnerabilities exist in the JavaScript engine of
    Foxit Software's PDF Reader.

  - The flaws exist within the parsing of U3D files. The issue results from the
    lack of validating the existence of an object prior to performing operations on
    the object.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Foxit Reader version 12.0.1.12430 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader 12.0.2 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/pdf-reader");
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos['version'];
pdfPath = infos['location'];

if(version_is_less(version:pdfVer, test_version:"12.0.2"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"12.0.2", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
