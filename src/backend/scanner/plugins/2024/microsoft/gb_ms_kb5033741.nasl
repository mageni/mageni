# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832780");
  script_version("2024-01-24T14:38:46+0000");
  script_cve_id("CVE-2024-21319", "CVE-2024-0056", "CVE-2024-0057");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 18:47:00 +0000 (Tue, 16 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-11 12:22:04 +0530 (Thu, 11 Jan 2024)");
  script_name(".NET Core Multiple Vulnerabilities (KB5033741)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5033741.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft Identity Denial of service vulnerability.

  - Microsoft.Data.SqlClient and System.Data.SqlClient SQL Data Provider Security Feature Bypass Vulnerability.

  - NET, .NET Framework, and Visual Studio Security Feature Bypass Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to conduct denial of service and secuirity feature bypass on an
  affected system.");

  script_tag(name:"affected", value:".NET Core runtime 8.0 before 8.0.1 and
  .NET Core SDK before 8.0.101.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtime to version 8.0.1
  or later or upgrade .NET Core SDK to version 8.0.101 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.1/8.0.1.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(!coreVers || coreVers !~ "^8\.0") {
  exit(0);
}

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")){
    exit(0);
  }
}

if(corerunVer) {
  if(corerunVer =~ "^8\.0" && version_is_less(version:corerunVer, test_version:"8.0.1")) {
    fix = "8.0.1 or later";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"8.0", test_version2:"8.0.100")) {
    fix1 = "8.0.101 or later";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core runtimes " + corerunVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core runtimes version " + fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

else if(fix1) {
  report = report_fixed_ver(installed_version:"ASP .NET Core With Microsoft .NET Core SDK " + codesdkVer,
               fixed_version:"ASP .NET Core With Microsoft .NET Core SDK version " + fix1, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
