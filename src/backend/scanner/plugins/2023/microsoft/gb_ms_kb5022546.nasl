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

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826772");
  script_version("2023-01-12T10:12:15+0000");
  script_cve_id("CVE-2023-21538");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 09:52:21 +0530 (Wed, 11 Jan 2023)");
  script_name(".NET Core Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:".NET Core is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a stack overflow vulnerability
  in .NET.");

  script_tag(name:"impact", value:"Successful exploitation cause a stack overflow
  which may result in a denial of service attack when an attacker sends an invalid
  request to an exposed endpoint.");

  script_tag(name:"affected", value:".NET Core runtime 6.0 before 6.0.13 and
  .NET Core SDK before 6.0.113 and 6.0.308.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  6.0.13 or later or upgrade .NET Core SDK to versions 6.0.113 or 6.0.308 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.13/6.0.13.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(!coreVers || coreVers !~ "^(3\.1|[6|7]\.0)"){
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver"))
{
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer)
{
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.12")){
    fix = "6.0.13 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.112") ||
     version_in_range(version:codesdkVer, test_version:"6.0.300", test_version2:"6.0.307")){
    fix1 = "6.0.113 or 6.0.308 or later";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(data:report);
  exit(0);
}

else if(fix1)
{
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
