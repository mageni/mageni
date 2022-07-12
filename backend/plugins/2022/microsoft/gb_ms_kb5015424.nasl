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

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821268");
  script_version("2022-06-15T13:30:55+0000");
  script_cve_id("CVE-2022-30184");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-15 13:30:55 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-15 09:18:47 +0530 (Wed, 15 Jun 2022)");
  script_name(".NET Core Information Disclosure Vulnerability (KB5015424)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5015424.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an excessive data output
  by the application in .NET.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain unauthorized access to sensitive information on the system.");

  script_tag(name:"affected", value:".NET Core versions 3.1 prior to 3.1.26,
  6.0 prior to 6.0.6.");

  script_tag(name:"solution", value:"Upgrade .NET Core to version 3.1.26 or 6.0.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.6/6.0.6.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.26/3.1.26.md");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(!vers || (vers !~ "^3\.1" && vers !~ "^6\.0")){
  exit(0);
}

if (version_is_less(version:vers, test_version:"3.1.26")){
  fix = "3.1.26";
}
else if(vers =~ "^6\." && version_is_less(version:vers, test_version:"6.0.6")){
  fix = "6.0.6";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
