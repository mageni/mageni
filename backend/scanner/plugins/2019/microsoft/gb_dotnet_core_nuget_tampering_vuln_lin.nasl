# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

CPE = "cpe:/a:microsoft:.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814698");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2019-0757");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-13 08:37:41 +0530 (Wed, 13 Mar 2019)");
  script_name("Microsoft .NET Core NuGet Package Manager Tampering Vulnerability - Linux");

  script_tag(name:"summary", value:"The host is installed with .NET Core
  and is prone to tampering vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  permissions on folders inside the NuGet packages folder structure.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an authenticated attacker to modify a NuGet package's folder structure.
  An attacker who successfully exploited this vulnerability could potentially
  modify files and folders that are unpackaged on a system.");

  script_tag(name:"affected", value:"Microsoft .NET Core 1.0 before 1.0.15, 1.1 before 1.1.12,
  2.1 before 2.1.9 and 2.2 before 2.2.3 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Microsoft .NET Core version 1.0.15 or 1.1.12
  or 2.1.9 or 2.2.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0757");
  script_xref(name:"URL", value:"https://devblogs.microsoft.com/dotnet/net-core-march-2019");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dotnet_core_runtime_detect_lin.nasl");
  script_mandatory_keys("dotnet/core/runtime/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

dot_ver = infos['version'];
dot_path = infos['location'];

if(version_in_range(version:dot_ver, test_version:"1.0", test_version2:"1.0.14")){
  fix = "1.0.15";
}
else if(version_in_range(version:dot_ver, test_version:"1.1", test_version2:"1.1.11")){
  fix = "1.1.12";
}
else if(version_in_range(version:dot_ver, test_version:"2.1", test_version2:"2.1.8")){
  fix = "2.1.9";
}
else if(version_in_range(version:dot_ver, test_version:"2.2", test_version2:"2.2.2")){
  fix = "2.2.3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:dot_ver, fixed_version:fix, install_path:dot_path);
  security_message(data:report);
  exit(0);
}
exit(99);
