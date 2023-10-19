# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:asp.net_core";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832298");
  script_version("2023-10-17T05:05:34+0000");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 10:17:06 +0530 (Wed, 11 Oct 2023)");
  script_name(".NET Core HTTP2 Rapid Reset Attack DoS Vulnerability (Windows)");

  script_tag(name:"summary", value:".NET Core is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a vulnerability which
  exists in the ASP.NET Core Kestrel web server where a malicious client may
  flood the server with specially crafted HTTP/2 requests, causing denial of service.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to cause denial of service on an affected system.");

  script_tag(name:"affected", value:".NET Core runtime 6.0 before 6.0.23 and
  .NET Core SDK before 6.0.123, 6.0.318.");

  script_tag(name:"solution", value:"Upgrade runtime to version 6.0.23 or
  SDK to 6.0.123 or 6.0.318 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.21/6.0.21.md");
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

if(!vers || vers !~ "^6\.0")
  exit(0);

if(!corerunVer = get_kb_item(".NET/Core/Runtime/Ver")) {
  if(!codesdkVer = get_kb_item(".NET/Core/SDK/Ver")) {
    exit(0);
  }
}

if(corerunVer) {
  if(version_in_range(version:corerunVer, test_version:"6.0", test_version2:"6.0.22")) {
    fix = "6.0.23 or later";
  }
}

else if(codesdkVer) {
  if(version_in_range(version:codesdkVer, test_version:"6.0", test_version2:"6.0.122") ||
     version_in_range(version:codesdkVer, test_version:"6.0.300", test_version2:"6.0.317")) {
    fix1 = "6.0.123 or 6.0.318 or later";
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
