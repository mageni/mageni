# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832224");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2023-33170", "CVE-2023-33127");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 10:51:38 +0530 (Wed, 12 Jul 2023)");
  script_name(".NET Core Multiple Vulnerabilities (KB5028705, KB5028706) - Windows");

  script_tag(name:"summary", value:".NET Core prone to security feature bypass
  and elevation of prvilege vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A vulnerability exists in .NET applications where the diagnostic server can be
    exploited to achieve cross-session/cross-user elevation of privilege (EoP) and
    code execution.

  - A vulnerability exists in ASP.NET Core applications where account lockout
    maximum failed attempts may not be immediately updated, allowing an attacker to
    try more passwords.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to bypass security restrictions, achieve cross-session/cross-user elevation of
  privilege (EoP) and code execution.");

  script_tag(name:"affected", value:".NET Core runtime 6.0 before 6.0.20, 7.0 before
  7.0.9 and .NET Core SDK before 6.0.120, 6.0.315, 7.0.306.");

  script_tag(name:"solution", value:"Upgrade .NET Core runtimes to versions
  6.0.20 or 7.0.9 or later or upgrade .NET Core SDK to versions 6.0.120 or 6.0.315 or
  7.0.306 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.20/6.0.20.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.9/7.0.9.md");
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

vers = infos["version"];
path = infos["location"];

if(!vers || vers !~ "^[6|7]\.0")
  exit(0);

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.19")) {
    fix = "6.0.20 or later";
  } else if(version_in_range(version:corerunVer, test_version:"7.0", test_version2:"7.0.8")) {
      fix = "7.0.9 or later";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.119") ||
     version_in_range(version:codesdkVer, test_version:"6.0.300", test_version2:"6.0.314")) {
    fix1 = "6.0.120 or 6.0.315 or later";
  }
  else if(version_in_range(version:codesdkVer, test_version:"7.0.300", test_version2:"7.0.305")) {
    fix1 = "7.0.306 or later";
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
