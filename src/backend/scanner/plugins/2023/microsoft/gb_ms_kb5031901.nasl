# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832299");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2023-38171", "CVE-2023-36435", "CVE-2023-44487");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-10 18:20:00 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 10:17:06 +0530 (Wed, 11 Oct 2023)");
  script_name(".NET Core Multiple DoS Vulnerabilities (Windows)");

  script_tag(name:"summary", value:".NET Core is prone to multiple denial of service
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A vulnerability exists in the ASP.NET Core Kestrel web server where a
    malicious client may flood the server with specially crafted HTTP/2 requests,
    causing denial of service.

  - A null pointer vulnerability exists in MsQuic.dll which may lead to
    Denial of Service.

  - A memory leak vulnerability exists in MsQuic.dll which may lead to
    Denial of Service.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to cause denial of service on an affected system.");

  script_tag(name:"affected", value:".NET Core runtime 7.0 before 7.0.12 and
  .NET Core SDK before 7.0.402.");

  script_tag(name:"solution", value:"Upgrade runtime to version 7.0.12 or SDK
  to 7.0.402 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/7.0/7.0.12/7.0.12.md");
  script_xref(name:"URL", value:"https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/");
  script_xref(name:"URL", value:"https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/6");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
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

if(!vers || vers !~ "^7\.0")
  exit(0);

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"7.0.11")) {
    fix = "7.0.12 or later";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"7.0", test_version2:"7.0.401")) {
    fix1 = "7.0.402 or later";
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
