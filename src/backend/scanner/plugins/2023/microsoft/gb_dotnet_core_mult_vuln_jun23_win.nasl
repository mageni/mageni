# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832090");
  script_version("2023-07-03T05:06:07+0000");
  script_cve_id("CVE-2023-33135", "CVE-2023-33128", "CVE-2023-33126", "CVE-2023-24936",
                "CVE-2023-24897", "CVE-2023-29331", "CVE-2023-24895", "CVE-2023-32032");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-03 05:06:07 +0000 (Mon, 03 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 11:40:38 +0530 (Wed, 14 Jun 2023)");
  script_name(".NET Core Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:".NET Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in XAML Frame elements.

  - A Remote Code Execution Vulnerability in DataTable from XML.

  - A Denial of Service Vulnerability in .NET source generator.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct remote code execution on an affected system.");

  script_tag(name:"affected", value:".NET Core runtime 7.0 before 7.0.7, 6.0 before
  6.0.18 and .NET Core SDK before 6.0.313 and 7.0 before 7.0.304.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  7.0.7 or 6.0.18 or later or upgrade .NET Core SDK to versions 6.0.118 or 7.0.304 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.7/7.0.7.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.18/6.0.18.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys("ASP.NET/Core/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

coreVers = infos["version"];
path = infos["location"];

if(!coreVers || coreVers !~ "^[6|7]\.0"){
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
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.17")){
    fix = "6.0.18 or later";
  }
  else if(version_in_range(version:corerunVer, test_version:"7.0", test_version2:"7.0.6")){
    fix = "7.0.7 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.312")){
    fix1 = "6.0.313 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.303")){
    fix1 = "7.0.304 or later";
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

exit(99);
