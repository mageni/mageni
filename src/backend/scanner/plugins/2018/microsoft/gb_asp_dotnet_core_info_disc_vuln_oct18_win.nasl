###############################################################################
# OpenVAS Vulnerability Test
#
# .NET Core Information Disclosure Vulnerability Oct18 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814093");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2018-8292");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-11 11:56:04 +0530 (Thu, 11 Oct 2018)");
  script_name(".NET Core Information Disclosure Vulnerability Oct18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with .NET Core
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when .NET Core when HTTP
  authentication information is inadvertently exposed in an outbound request that
  encounters an HTTP redirect.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information and use the information to further compromise
  the web application.");

  script_tag(name:"affected", value:".NET Core 1.0.x runtime 1.0.12 or lower,

 .NET Core 1.1.x runtime 1.1.9 or lower,

 .NET Core 2.0.x runtime,

 .NET Core SDK prior to version 1.1.11.");

  script_tag(name:"solution", value:"Upgrade to 1.0.13, 1.1.10 or 2.1 or later for
  .NET Core runtimes and to 1.1.11 for .NET Core SDK. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/corefx/issues/32730");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-8292");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(!coreVers || coreVers !~ "^(1\.[01]|2\.0)"){
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
  if(version_in_range(version:corerunVer, test_version:"1.0", test_version2:"1.0.12")){
    fix = "1.0.13";
  }
  else if(version_in_range(version:corerunVer, test_version:"1.1", test_version2:"1.1.9")){
    fix = "1.1.10";
  }
  else if(corerunVer =~ "^2\.0"){
    fix = "2.1";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"1.1", test_version2:"1.1.10")){
    fix1 = "1.1.11";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:".NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:".NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(data:report);
  exit(0);
}

else if(fix1)
{
  report = report_fixed_ver(installed_version:".NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:".NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(0);
