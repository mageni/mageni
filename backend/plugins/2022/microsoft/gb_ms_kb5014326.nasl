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
  script_oid("1.3.6.1.4.1.25623.1.0.821236");
  script_version("2022-05-11T13:16:47+0000");
  script_cve_id("CVE-2022-29145", "CVE-2022-29117", "CVE-2022-23267");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-12 09:56:58 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-11 09:38:52 +0530 (Wed, 11 May 2022)");
  script_name(".NET Core Multiple Denial of Service Vulnerabilities (KB5014326)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5014326.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an insufficient
  validation of user-supplied input in .NET and Visual Studio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause a denial of service condition on affected systems.");

  script_tag(name:"affected", value:".NET Core versions 3.1 prior to 3.1.25.");

  script_tag(name:"solution", value:"Upgrade .NET Core to version 3.1.25 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/3.1/3.1.25/3.1.25.md");

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

if(!vers || vers !~ "^3\.1"){
  exit(0);
}

if (version_is_less(version:vers, test_version:"3.1.25"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.1.25", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
