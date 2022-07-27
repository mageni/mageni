###############################################################################
# OpenVAS Vulnerability Test
#
# ASP.NET Core Multiple Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##########################################################################

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812950");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-0785", "CVE-2018-0784");
  script_bugtraq_id(102379, 102377);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-27 12:03:33 +0530 (Tue, 27 Feb 2018)");
  script_name("ASP.NET Core Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error in the ASP.NET Core web application, created using vulnerable
    project templates, which fails to properly sanitize web requests.

  - An error in the individual authentication templates for ASP.NET Core.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited these vulnerabilities to change the recovery codes
  associated with the victim's user account without his/her consent.");

  script_tag(name:"affected", value:"ASP.NET Core 2.0 with .NET SDK version
  2.0.0, 2.0.2, 2.0.3, 2.1.2 and 2.1.3");

  script_tag(name:"solution", value:"Upgrade to ASP.NET Core 2.0 with .NET SDK
  version 2.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/284");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/285");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver", ".NET/Core/SDK/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
coreVers = infos['version'];
path = infos['location'];

if(coreVers =~ "2.0")
{
  sdkVer = get_kb_item(".NET/Core/SDK/Ver");
  affected = make_list("2.0.0", "2.0.2", "2.0.3", "2.1.2", "2.1.3");
  foreach affecVer (affected)
  {
    if(sdkVer == affecVer)
    {
      report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + sdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK 2.1.4", install_path:path);
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);
