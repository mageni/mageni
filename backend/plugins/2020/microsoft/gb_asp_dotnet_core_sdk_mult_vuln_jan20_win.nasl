# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816557");
  script_version("2020-01-17T10:38:45+0000");
  script_cve_id("CVE-2020-0602", "CVE-2020-0603", "CVE-2020-0605", "CVE-2020-0606");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-17 10:38:45 +0000 (Fri, 17 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-16 11:32:54 +0530 (Thu, 16 Jan 2020)");
  script_name(".NET Core SDK Multiple Vulnerabilities (Jan 2020");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core
  SDK and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error when ASP.NET Core improperly handles web requests.

  - An error in ASP.NET Core software when the software fails to handle objects
    in memory.

  - Multiple errors in .NET software when the software fails to check the source markup
    of a file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user and conduct DoS attacks.");

  script_tag(name:"affected", value:"ASP.NET Core SDK 3.0.x prior to 3.0.102 and 3.1.x
  prior to 3.1.101");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core to 3.1.101 or 3.0.102 or later.
  For updates refer the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/3.0/3.0.2/3.0.2.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/3.1/3.1.1/3.1.1.md");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0606");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0605");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0603");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0602");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys(".NET/Core/SDK/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if (coreVers =~ "^3\.0" && version_is_less(version:coreVers, test_version:"3.0.102")){
  fix = "3.0.102";
}

else if (coreVers =~ "^3\.1" && version_is_less(version:coreVers, test_version:"3.1.101")){
  fix = "3.1.101" ;
}

if(fix)
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
