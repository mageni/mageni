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
  script_oid("1.3.6.1.4.1.25623.1.0.821204");
  script_version("2022-05-10T09:57:45+0000");
  script_cve_id("CVE-2022-28250", "CVE-2022-28251", "CVE-2022-28252", "CVE-2022-28253",
                "CVE-2022-28254", "CVE-2022-28255", "CVE-2022-28256", "CVE-2022-28257",
                "CVE-2022-28258", "CVE-2022-28259", "CVE-2022-28260", "CVE-2022-28261",
                "CVE-2022-28262", "CVE-2022-28263", "CVE-2022-28264", "CVE-2022-28265",
                "CVE-2022-28266", "CVE-2022-28267", "CVE-2022-28268", "CVE-2022-28239",
                "CVE-2022-28240", "CVE-2022-28241", "CVE-2022-28242", "CVE-2022-28243",
                "CVE-2022-27800", "CVE-2022-27802", "CVE-2022-24101", "CVE-2022-27785",
                "CVE-2022-27786", "CVE-2022-27787", "CVE-2022-27788", "CVE-2022-27790",
                "CVE-2022-27791", "CVE-2022-27792", "CVE-2022-27793", "CVE-2022-27794",
                "CVE-2022-27797", "CVE-2022-27798", "CVE-2022-27801", "CVE-2022-28231",
                "CVE-2022-28232", "CVE-2022-28233", "CVE-2022-28236", "CVE-2022-28237",
                "CVE-2022-28238", "CVE-2022-28245", "CVE-2022-28246", "CVE-2022-28248",
                "CVE-2022-28269", "CVE-2022-24102", "CVE-2022-24103", "CVE-2022-24104",
                "CVE-2022-27795", "CVE-2022-27796", "CVE-2022-27799", "CVE-2022-28230",
                "CVE-2022-28235", "CVE-2022-28249", "CVE-2022-27789", "CVE-2022-28247",
                "CVE-2022-28244", "CVE-2022-28234");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-11 10:22:31 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2022-04-29 12:15:42 +0530 (Fri, 29 Apr 2022)");
  script_name("Adobe Reader DC Continuous Security Update (APSB22-16) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Heap-based buffer overflow errors.

  - Missing support for integrity check.

  - Violation of secure design principles.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, escalate privileges and disclose sensitive information
  on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Reader DC (Continuous) versions
  22.001.20085 and earlier on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader DC (Continuous)
  to version 2022.001.20117 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-16.html");
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

if(version_is_less(version:vers, test_version:"22.001.20117"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"2022.001.20117", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
