# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832237");
  script_version("2023-08-11T16:09:05+0000");
  script_cve_id("CVE-2018-8269");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-08-11 16:09:05 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2023-08-07 15:40:27 +0530 (Mon, 07 Aug 2023)");
  script_name(".NET Core OData Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:".NET Core is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when OData Library improperly
  handles web request");

  script_tag(name:"impact", value:"Successful exploitation would allow
  attackers to cause a denial of service against an OData web application.");

  script_tag(name:"affected", value:".NET Core runtime 2.1 before 2.1.13, 2.2 before
  2.2.7 and .NET Core SDK before 2.1.509, 2.1.606, 2.1.802, 2.2.109, 2.2.206 and 2.2.402.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  2.1.13 or 2.2.7 or later or upgrade .NET Core SDK to versions 2.1.509 or 2.1.606
  or 2.1.802 or 2.2.109 or 2.2.206 or 2.2.402 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/aspnet/Announcements/issues/385");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(!coreVers || coreVers !~ "^2\.[12]") {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"2.1", test_version2:"2.1.12")) {
    fix = "2.1.13";
  }
  else if(version_in_range(version:corerunVer, test_version:"2.2", test_version2:"2.2.6")) {
    fix = "2.2.7";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"2.1", test_version2:"2.1.508") ||
     version_in_range(version:codesdkVer, test_version:"2.1.600", test_version2:"2.1.605") ||
     version_in_range(version:codesdkVer, test_version:"2.1.800", test_version2:"2.1.801")) {
     fix1 = "SDK 2.1.509 for Visual Studio 2017 or SDK 2.1.606 for Visual Studio 2019 (v16.0) or SDK 2.1.802 for Visual Studio 2019 (v16.2)";
  }
  else if(version_in_range(version:codesdkVer, test_version:"2.2", test_version2:"2.2.108") ||
          version_in_range(version:codesdkVer, test_version:"2.2.200", test_version2:"2.2.205") ||
          version_in_range(version:codesdkVer, test_version:"2.2.400", test_version2:"2.2.401")) {
     fix1 = "SDK 2.2.109 for Visual Studio 2017 or SDK 2.2.206 for Visual Studio 2019 (v16.0) or SDK 2.2.402 for Visual Studio 2019 (v16.2)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(data:report);
  exit(0);
}

else if(fix1){
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(0);
