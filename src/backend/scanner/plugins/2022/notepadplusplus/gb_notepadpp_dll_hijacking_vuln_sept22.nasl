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

CPE = "cpe:/a:notepad-plus-plus:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826490");
  script_version("2022-10-04T10:10:56+0000");
  script_cve_id("CVE-2022-32168");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-04 10:10:56 +0000 (Tue, 04 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-09-30 12:15:00 +0530 (Fri, 30 Sep 2022)");
  script_name("Notepad++ DLL hijacking Vulnerability - Sept22");

  script_tag(name:"summary", value:"Notepad++ is prone to a DLL hijacking
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to dll hijacking
  vulnerability in UxTheme.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Notepad++ version 8.3 through 8.4.4
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Notepad++ version 8.4.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/notepad-plus-plus/notepad-plus-plus/commit/85d7215d9b3e0d5a8433fc31aec4f2966821051e");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_notepadpp_detect_portable_win.nasl");
  script_mandatory_keys("Notepad++64/Win/installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"8.3", test_version2:"8.4.4")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.4.5", install_path:path );
  security_message(data:report);
  exit(0);
}
exit(99);