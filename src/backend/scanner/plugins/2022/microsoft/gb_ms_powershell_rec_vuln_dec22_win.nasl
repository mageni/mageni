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

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821327");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2022-41076");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 15:45:33 +0530 (Wed, 14 Dec 2022)");
  script_name("Microsoft PowerShell Remote Code Execution Vulnerability - Dec 2022 (Windows)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2022-41076.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when specially crafted ANSI
  control sequences are used through the pipeline to create executable code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute the code.");

  script_tag(name:"affected", value:"PowerShell Core versions 7.2 to 7.2.7 and 7.3.0 on Windows.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 7.3.1 or 7.2.8
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/35");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41076");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(vers =~ "^7\.")
{
  if(version_is_equal(version: vers, test_version: "7.3.0")){
    fix = "7.3.1";
  }

  if(version_in_range_exclusive(version: vers, test_version_lo: "7.2", test_version_up: "7.2.8")){
    fix = "7.2.8";
  }

  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
