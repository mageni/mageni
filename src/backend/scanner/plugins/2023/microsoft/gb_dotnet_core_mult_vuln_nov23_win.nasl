# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832631");
  script_version("2023-11-23T05:06:17+0000");
  script_cve_id("CVE-2023-36038");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-11-23 05:06:17 +0000 (Thu, 23 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-20 20:36:00 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 11:59:24 +0530 (Thu, 16 Nov 2023)");
  script_name(".NET Core Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:".NET Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:

  - A vulnerability exists in ASP.NET IIS where a remote unauthenticated user can
   issue specially crafted requests to a .NET application which may result in denial of service.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause denial of service on an affected system.");

  script_tag(name:"affected", value:".NET Core runtime 8.0 before 8.0.0 and
  .NET Core SDK before 8.0.100.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtime to version 8.0.0 or later
  or upgrade .NET Core SDK to version 8.0.100 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/286");
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

if(!coreVers || coreVers !~ "^8\.0"){
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
  ## .NET 8.0 RC2 or earlier is vulnerable
  if(corerunVer =~ "^8\.0\.0" && corerunVer !~ "^8\.0\.0$"){
    fix = "8.0.0 or later";
  }
}

else if(codesdkVer)
{
  if(version_in_range(version:codesdkVer, test_version:"8.0", test_version2:"8.0.99")){
    fix1 = "8.0.100 or later";
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
