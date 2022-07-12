###############################################################################
# OpenVAS Vulnerability Test
#
# ASP.NET Core Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813043");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2018-0875");
  script_bugtraq_id(103225);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-16 11:09:04 +0530 (Fri, 16 Mar 2018)");
  script_name("ASP.NET Core Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with ASP.NET Core
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the way that .NET Core
  handles specially crafted requests, causing a hash collision.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause performance to degrade significantly enough to cause a
  denial of service condition.");

  script_tag(name:"affected", value:".NET Core 1.0.9 and prior, 1.1.x to 1.1.6, and 2.0.x to  2.0.5 and
  .NET Core SDK prior to versions 1.1.8, 2.1.x to 2.1.101.");

  script_tag(name:"solution", value:"Upgrade to .NET Core runtimes to versions
  1.0.10, 1.1.7 or 2.0.6 or later or upgrade to .NET Core SDK to versions 1.1.8
  or 2.1.101 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/62");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/master/release-notes/2.1/2.1.0-preview1.md");

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
  if(version_in_range(version:corerunVer, test_version:"1.0", test_version2:"1.0.9")){
    fix = "1.0.10";
  }
  else if(version_in_range(version:corerunVer, test_version:"1.1", test_version2:"1.1.6")){
    fix = "1.1.7";
  }
  else if(version_in_range(version:corerunVer, test_version:"2.0", test_version2:"2.0.5")){
    fix = "2.0.6";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"1.1", test_version2:"1.1.7")){
    fix1 = "1.1.8";
  }
  else if(version_in_range(version:codesdkVer, test_version:"2.1", test_version2:"2.1.100")){
    fix1 = "2.1.101";
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
